#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

struct DesktopState {
    bridge: Arc<Mutex<Option<BridgeProcess>>>,
    workspace: Arc<Mutex<Option<PathBuf>>>,
    finding_files: Arc<Mutex<HashMap<String, PathBuf>>>,
    finding_exports: Arc<Mutex<HashMap<String, Value>>>,
    report_artifacts: Arc<Mutex<HashMap<String, PathBuf>>>,
}

struct BridgeProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

#[derive(Deserialize, Serialize)]
struct SavedProject {
    version: u8,
    project_path: String,
}

fn saved_project_file(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_config_dir().map(|directory| directory.join("last-project.json")).map_err(|error| format!("Desktop project settings are unavailable: {error}"))
}

fn save_project_path(file: &Path, project: &Path) -> Result<(), String> {
    let directory = file.parent().ok_or("Desktop project settings path is invalid")?;
    std::fs::create_dir_all(directory).map_err(|error| format!("Unable to create Desktop project settings: {error}"))?;
    let saved = SavedProject { version: 1, project_path: project.to_string_lossy().into_owned() };
    let contents = serde_json::to_vec(&saved).map_err(|error| format!("Unable to encode Desktop project settings: {error}"))?;
    std::fs::write(file, contents).map_err(|error| format!("Unable to save the last Desktop project: {error}"))
}

fn clear_saved_project(file: &Path) {
    let _ = std::fs::remove_file(file);
}

fn load_project_path(file: &Path) -> Option<PathBuf> {
    let contents = match std::fs::read_to_string(file) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => { clear_saved_project(file); return None; }
    };
    let saved = match serde_json::from_str::<SavedProject>(&contents) {
        Ok(saved) if saved.version == 1 && !saved.project_path.trim().is_empty() => saved,
        _ => { clear_saved_project(file); return None; }
    };
    match PathBuf::from(saved.project_path).canonicalize() {
        Ok(project) if project.is_dir() => Some(project),
        _ => { clear_saved_project(file); None }
    }
}

fn canonical_project_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    path.canonicalize().map(|canonical| node_compatible_path(&canonical))
}

fn persist_selected_project(file: &Path, requested: &Path, current: &Path) -> Result<(), String> {
    let selected = canonical_project_path(requested).map_err(|_| "Selected project folder is unavailable")?;
    if !selected.is_dir() { return Err("Selected project path is not a folder".into()); }
    let current = canonical_project_path(current).map_err(|error| format!("Unable to verify the selected project folder: {error}"))?;
    if selected != current { return Err("Project selection changed before it could be saved".into()); }
    save_project_path(file, &selected)
}

#[tauri::command]
fn restore_last_project(app: AppHandle, state: State<'_, DesktopState>) -> Result<Option<String>, String> {
    let file = saved_project_file(&app)?;
    let project = load_project_path(&file);
    let mut workspace = state.workspace.lock().map_err(|_| "Workspace selection unavailable")?;
    *workspace = project.clone();
    Ok(project.and_then(|path| path.to_str().map(str::to_owned)))
}

#[tauri::command]
fn remember_project(app: AppHandle, state: State<'_, DesktopState>, workspace_root: String) -> Result<(), String> {
    let current = state.workspace.lock().map_err(|_| "Workspace selection unavailable")?.clone().ok_or("Select a project folder first")?;
    persist_selected_project(&saved_project_file(&app)?, Path::new(&workspace_root), &current)
}

#[tauri::command]
fn forget_project(app: AppHandle, state: State<'_, DesktopState>) -> Result<(), String> {
    let file = saved_project_file(&app)?;
    clear_saved_project(&file);
    *state.workspace.lock().map_err(|_| "Workspace selection unavailable")? = None;
    state.report_artifacts.lock().map_err(|_| "Report artifact list unavailable")?.clear();
    Ok(())
}

impl Drop for BridgeProcess {
    fn drop(&mut self) {
        // EOF asks the Node bridge to stop Core and emit its final disconnect event.
        // Keep stdout open until that orderly shutdown has completed to avoid racing
        // a final bridge write against a closed pipe.
        self.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                _ => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl BridgeProcess {
    fn write_request(&mut self, request: &Value) -> Result<(), std::io::Error> {
        let stdin = self.stdin.as_mut().ok_or_else(|| std::io::Error::new(ErrorKind::BrokenPipe, "Desktop bridge stdin is closed"))?;
        writeln!(stdin, "{request}")?;
        stdin.flush()
    }
}

#[tauri::command]
async fn core_request(
    app: AppHandle,
    state: State<'_, DesktopState>,
    method: String,
    params: Value,
) -> Result<Value, String> {
    let app = app.clone();
    let bridge = state.bridge.clone();
    let workspace = state.workspace.clone();
    let finding_files = state.finding_files.clone();
    let finding_exports = state.finding_exports.clone();
    let report_artifacts = state.report_artifacts.clone();
    tauri::async_runtime::spawn_blocking(move || {
        core_request_blocking(app, bridge, workspace, finding_files, finding_exports, report_artifacts, method, params)
    })
    .await
    .map_err(|e| format!("Desktop Core task failed: {e}"))?
}

fn core_request_blocking(
    app: AppHandle,
    bridge_state: Arc<Mutex<Option<BridgeProcess>>>,
    workspace_state: Arc<Mutex<Option<PathBuf>>>,
    finding_files: Arc<Mutex<HashMap<String, PathBuf>>>,
    finding_exports: Arc<Mutex<HashMap<String, Value>>>,
    report_artifacts: Arc<Mutex<HashMap<String, PathBuf>>>,
    method: String,
    supplied_params: Value,
) -> Result<Value, String> {
    const ALLOWED_METHODS: [&str; 19] = ["project.detect", "project.profile", "scan.start", "rag.index", "ai.providers", "ai.models", "ai.chat", "ai.cancel", "credentials.status", "credentials.set", "credentials.delete", "workspace.rules.get", "workspace.rules.set", "workspace.threat-history.get", "workspace.threat-history.delete", "workspace.agent-sessions.get", "workspace.agent-sessions.set", "workspace.recommendations.get", "workspace.reports.get"];
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return Err("Unsupported Core method".into());
    }
    let params = if method == "ai.providers" { json!({}) }
    else if method == "ai.models" { supplied_params }
    else if method == "ai.chat" || method == "ai.cancel" { supplied_params }
    else if method.starts_with("credentials.") { supplied_params }
    else {
        let workspace = workspace_state.lock().map_err(|_| "Workspace selection unavailable")?.clone().ok_or("Select a project folder first")?;
        let workspace = node_compatible_path(&workspace);
        if method == "rag.index" { json!({ "workspaceRoot": workspace, "withAi": supplied_params.get("withAi").and_then(Value::as_bool).unwrap_or(false) }) }
        else if method == "workspace.rules.set" { json!({ "workspaceRoot": workspace, "rules": supplied_params.get("rules").cloned().ok_or("Custom rules are required")? }) }
        else if method == "workspace.rules.get" { json!({ "workspaceRoot": workspace }) }
        else if method == "workspace.threat-history.get" { json!({ "workspaceRoot": workspace }) }
        else if method == "workspace.threat-history.delete" { json!({ "workspaceRoot": workspace, "snapshotId": supplied_params.get("snapshotId").cloned().ok_or("Threat snapshot id is required")? }) }
        else if method == "workspace.reports.get" { json!({ "workspaceRoot": workspace }) }
        else if method == "workspace.agent-sessions.get" || method == "workspace.recommendations.get" { json!({ "workspaceRoot": workspace }) }
        else if method == "workspace.agent-sessions.set" { json!({ "workspaceRoot": workspace, "sessions": supplied_params.get("sessions").cloned().ok_or("Agent sessions are required")? }) }
        else if method == "scan.start" { desktop_scan_params(&workspace, &supplied_params) }
        else { json!({ "workspaceRoot": workspace, "trusted": true }) }
    };
    let mut slot = bridge_state
        .lock()
        .map_err(|_| "Desktop Core bridge unavailable")?;
    if slot.is_none() {
        *slot = Some(start_bridge()?);
    }
    let bridge = slot.as_mut().ok_or("Desktop Core bridge failed to start")?;
    let id = format!(
        "desktop-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis()
    );
    let request = json!({"id": id, "method": method, "params": params});
    if let Err(error) = bridge.write_request(&request) {
        slot.take();
        return Err(format!("Desktop Core bridge disconnected: {error}"));
    }
    match read_response(&app, bridge, &id) {
        Ok(result) => {
            if method == "workspace.reports.get" {
                if let Some(root) = workspace_state.lock().ok().and_then(|value| value.clone()) {
                    if let Ok(mut artifacts) = report_artifacts.lock() {
                        artifacts.clear();
                        let reports_root = root.join(".aqiron-security").join("reports");
                        for (format, key) in [("pdf", "pdfPath"), ("json", "jsonPath"), ("sarif", "sarifPath")] {
                            if let Some(path) = result.get(key).and_then(Value::as_str).map(PathBuf::from) {
                                if let (Ok(base), Ok(candidate)) = (reports_root.canonicalize(), path.canonicalize()) {
                                    if candidate.starts_with(base) && candidate.is_file() { artifacts.insert(format.to_owned(), candidate); }
                                }
                            }
                        }
                    }
                }
            }
            if method == "scan.start" {
                if let Some(findings) = result.get("findings").and_then(Value::as_array) {
                    if let (Some(root), Ok(mut allowed), Ok(mut exports)) = (workspace_state.lock().ok().and_then(|value| value.clone()), finding_files.lock(), finding_exports.lock()) {
                        allowed.clear(); exports.clear();
                        for finding in findings {
                            if let (Some(id), Some(file)) = (finding.get("id").and_then(Value::as_str), finding.get("file").and_then(Value::as_str)) {
                                let candidate = PathBuf::from(file);
                                if candidate.is_absolute() && candidate.starts_with(&root) {
                                    allowed.insert(id.to_owned(), candidate);
                                    let keys = ["id", "title", "description", "severity", "ruleId", "file", "line", "column", "sourceTool", "cwe", "owasp", "status", "confidence", "riskScore", "remediation", "tags"];
                                    let safe = keys.iter().filter_map(|key| finding.get(*key).map(|value| ((*key).to_owned(), value.clone()))).collect::<serde_json::Map<_, _>>();
                                    exports.insert(id.to_owned(), Value::Object(safe));
                                }
                            }
                        }
                    }
                }
            }
            Ok(result)
        },
        Err(error) => {
            slot.take();
            Err(error)
        }
    }
}

fn desktop_scan_params(workspace: &Path, supplied_params: &Value) -> Value {
    json!({
        "workspaceRoot": node_compatible_path(workspace),
        "trusted": true,
        "mode": supplied_params.get("mode").cloned().unwrap_or(json!("deep")),
    })
}

#[tauri::command]
async fn open_finding_file(state: State<'_, DesktopState>, finding_id: String) -> Result<(), String> {
    let root = state.workspace.lock().map_err(|_| "Workspace selection unavailable")?.clone().ok_or("Select a project folder first")?;
    let candidate = state.finding_files.lock().map_err(|_| "Finding file list unavailable")?.get(&finding_id).cloned().ok_or("That finding is not part of the current scan")?;
    let root = root.canonicalize().map_err(|_| "Selected project folder is unavailable")?;
    let file = candidate.canonicalize().map_err(|_| "Finding file no longer exists")?;
    if !file.is_file() || !file.starts_with(&root) { return Err("Finding file is outside the selected project or is not a file".into()); }
    open_with_default_app(&file)
}

#[tauri::command]
async fn export_finding(app: AppHandle, state: State<'_, DesktopState>, finding_id: String) -> Result<Option<String>, String> {
    let finding = state.finding_exports.lock().map_err(|_| "Finding export data unavailable")?.get(&finding_id).cloned().ok_or("That finding is not part of the current scan")?;
    let suggested = finding.get("title").and_then(Value::as_str).unwrap_or("aqiron-finding").chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).take(72).collect::<String>();
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path) = app.dialog().file().add_filter("JSON finding", &["json"]).set_file_name(format!("{suggested}.json")).blocking_save_file() else { return Ok(None); };
        let path = path.into_path().map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(&finding).map_err(|e| e.to_string())?;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { "File already exists; choose a new name".to_owned() } else { format!("Unable to save finding: {e}") })?;
        file.write_all(&bytes).map_err(|e| format!("Unable to write finding: {e}"))?;
        Ok(path.to_str().map(str::to_owned))
    }).await.map_err(|e| format!("Finding export task failed: {e}"))?
}

#[tauri::command]
async fn save_report_artifact(app: AppHandle, format: String, report: Value) -> Result<Option<String>, String> {
    if !["pdf", "json", "sarif"].contains(&format.as_str()) { return Err("Unsupported report format".into()); }
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (name, ext, filter, bytes) = match format.as_str() {
            "pdf" => {
                let pdf = report.get("pdf").and_then(Value::as_str).ok_or("Core PDF artifact is unavailable")?;
                let bytes = pdf.chars().map(|character| u8::try_from(character as u32).map_err(|_| "Core PDF artifact contains invalid binary data")).collect::<Result<Vec<_>, _>>()?;
                ("aqiron-report.pdf", "pdf", "PDF document", bytes)
            }
            "json" => ("aqiron-report.json", "json", "JSON report", serde_json::to_vec_pretty(report.get("json").ok_or("Core JSON artifact is unavailable")?).map_err(|e| e.to_string())?),
            _ => ("aqiron-report.sarif", "sarif", "SARIF report", serde_json::to_vec_pretty(report.get("sarif").ok_or("Core SARIF artifact is unavailable")?).map_err(|e| e.to_string())?),
        };
        let Some(path) = app.dialog().file().add_filter(filter, &[ext]).set_file_name(name).blocking_save_file() else { return Ok(None); };
        let path = path.into_path().map_err(|e| e.to_string())?;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { "File already exists; choose a new name".to_owned() } else { format!("Unable to save report: {e}") })?;
        file.write_all(&bytes).map_err(|e| format!("Unable to write report: {e}"))?;
        Ok(path.to_str().map(str::to_owned))
    }).await.map_err(|e| format!("Report export task failed: {e}"))?
}

#[tauri::command]
async fn save_existing_report_artifact(app: AppHandle, state: State<'_, DesktopState>, format: String) -> Result<Option<String>, String> {
    if !["pdf", "json", "sarif"].contains(&format.as_str()) { return Err("Unsupported report format".into()); }
    let source = state.report_artifacts.lock().map_err(|_| "Report artifact list unavailable")?.get(&format).cloned().ok_or("That report artifact is not available for the active project")?;
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let extension = format.as_str();
        let filename = source.file_name().and_then(OsStr::to_str).unwrap_or("aqiron-report").to_owned();
        let Some(target) = app.dialog().file().add_filter(&format!("{} report", format.to_uppercase()), &[extension]).set_file_name(filename).blocking_save_file() else { return Ok(None); };
        let target = target.into_path().map_err(|error| error.to_string())?;
        let bytes = std::fs::read(&source).map_err(|error| format!("Unable to read existing report: {error}"))?;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&target).map_err(|error| if error.kind() == std::io::ErrorKind::AlreadyExists { "File already exists; choose a new name".to_owned() } else { format!("Unable to save report: {error}") })?;
        file.write_all(&bytes).map_err(|error| format!("Unable to write report: {error}"))?;
        Ok(target.to_str().map(str::to_owned))
    }).await.map_err(|error| format!("Report export task failed: {error}"))?
}

#[cfg(target_os = "windows")]
fn open_with_default_app(path: &Path) -> Result<(), String> {
    Command::new("explorer.exe").arg(path).spawn().map(|_| ()).map_err(|e| format!("Unable to open finding file: {e}"))
}
#[cfg(target_os = "macos")]
fn open_with_default_app(path: &Path) -> Result<(), String> {
    Command::new("open").arg(path).spawn().map(|_| ()).map_err(|e| format!("Unable to open finding file: {e}"))
}
#[cfg(all(unix, not(target_os = "macos")))]
fn open_with_default_app(path: &Path) -> Result<(), String> {
    Command::new("xdg-open").arg(path).spawn().map(|_| ()).map_err(|e| format!("Unable to open finding file: {e}"))
}

#[tauri::command]
async fn select_workspace(
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Option<String>, String> {
    let app = app.clone();
    let workspace = state.workspace.clone();
    let report_artifacts = state.report_artifacts.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selected = app
            .dialog()
            .file()
            .blocking_pick_folder()
            .map(|path| {
                path.into_path()
                    .map_err(|e| format!("Invalid selected folder: {e}"))
            })
            .transpose()?;
        let Some(path) = selected else {
            return Ok(None);
        };
        let path = path
            .canonicalize()
            .map_err(|e| format!("Unable to resolve selected project folder: {e}"))?;
        let path = node_compatible_path(&path);
        if !path.is_dir() {
            return Err("Selected project path is not a folder".into());
        }
        *workspace
            .lock()
            .map_err(|_| "Workspace selection unavailable")? = Some(path.clone());
        report_artifacts.lock().map_err(|_| "Report artifact list unavailable")?.clear();
        Ok(path.to_str().map(str::to_owned))
    })
    .await
    .map_err(|e| format!("Workspace picker failed: {e}"))?
}

fn start_bridge() -> Result<BridgeProcess, String> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .join("../../..")
        .canonicalize()
        .map_err(|e| format!("Unable to resolve repository root: {e}"))?;
    let root = node_compatible_path(&root);
    let bridge_path = root.join("dist/aqiron-desktop-bridge.js");
    let runtime_path = root.join("dist/core-runtime.js");
    if !bridge_path.is_file() {
        return Err("Desktop bridge is not built. Run npm run core:build.".into());
    }
    if !runtime_path.is_file() {
        return Err("Aqiron Core runtime is not built. Run npm run core:build.".into());
    }
    let node = resolve_node_binary(std::env::var_os("AQIRON_NODE_BINARY"));
    let mut child = desktop_bridge_command(&node, &bridge_path, &root, &runtime_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Unable to start Aqiron Core bridge: {e}"))?;
    Ok(BridgeProcess {
        stdin: Some(child
            .stdin
            .take()
            .ok_or("Desktop bridge stdin unavailable")?),
        stdout: BufReader::new(
            child
                .stdout
                .take()
                .ok_or("Desktop bridge stdout unavailable")?,
        ),
        child,
    })
}

fn resolve_node_binary(configured: Option<OsString>) -> OsString {
    configured
        .filter(|path| !path.to_string_lossy().trim().is_empty())
        .unwrap_or_else(|| OsString::from("node"))
}

fn desktop_bridge_command(
    node: &OsStr,
    bridge_path: &Path,
    root: &Path,
    runtime_path: &Path,
) -> Command {
    let mut command = Command::new(node);
    command
        .arg(bridge_path)
        .current_dir(root)
        .env("AQIRON_CORE_RUNTIME_PATH", runtime_path);
    command
}

fn node_compatible_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let value = path.as_os_str().to_string_lossy();
        if let Some(unc_path) = value.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{unc_path}"));
        }
        if let Some(drive_path) = value.strip_prefix(r"\\?\") {
            return PathBuf::from(drive_path);
        }
    }
    path.to_path_buf()
}

fn read_response(app: &AppHandle, bridge: &mut BridgeProcess, id: &str) -> Result<Value, String> {
    let mut line = String::new();
    loop {
        line.clear();
        if bridge
            .stdout
            .read_line(&mut line)
            .map_err(|e| format!("Desktop bridge connection lost: {e}"))?
            == 0
        {
            return Err("Aqiron Core disconnected".into());
        }
        let message: Value = serde_json::from_str(&line)
            .map_err(|e| format!("Invalid desktop bridge response: {e}"))?;
        if message.get("type").and_then(Value::as_str) == Some("event") {
            if let Some(event) = message.get("event") {
                let _ = app.emit("desktop-core-event", event);
            }
            continue;
        }
        if message.get("id").and_then(Value::as_str) != Some(id) {
            continue;
        }
        if message.get("success").and_then(Value::as_bool) == Some(true) {
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
        return Err(message
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Core request failed")
            .to_owned());
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DesktopState {
            bridge: Arc::new(Mutex::new(None)),
            workspace: Arc::new(Mutex::new(None)),
            finding_files: Arc::new(Mutex::new(HashMap::new())),
            finding_exports: Arc::new(Mutex::new(HashMap::new())),
            report_artifacts: Arc::new(Mutex::new(HashMap::new())),
        })
        .invoke_handler(tauri::generate_handler![core_request, select_workspace, restore_last_project, remember_project, forget_project, open_finding_file, export_finding, save_report_artifact, save_existing_report_artifact])
        .run(tauri::generate_context!())
        .expect("error while running Aqiron Security");
}

#[cfg(test)]
mod tests {
	use super::{canonical_project_path, clear_saved_project, desktop_bridge_command, desktop_scan_params, load_project_path, node_compatible_path, persist_selected_project, resolve_node_binary, save_project_path};
    use std::ffi::{OsStr, OsString};
	use std::path::{Path, PathBuf};

	fn test_directory() -> PathBuf {
		let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
		let directory = std::env::temp_dir().join(format!("aqiron-desktop-project-{}-{unique}", std::process::id()));
		std::fs::create_dir_all(&directory).unwrap();
		directory
	}

	#[test]
	fn desktop_scan_forwards_the_selected_mode_to_core() {
		let workspace = Path::new("C:\\projects\\flutter-app");
		let params = desktop_scan_params(workspace, &serde_json::json!({ "mode": "analysis" }));
		assert_eq!(params["mode"], "analysis");
		assert_eq!(params["workspaceRoot"], "C:\\projects\\flutter-app");
		assert_eq!(params["trusted"], true);
	}

	#[test]
	fn first_launch_without_saved_project_returns_no_project() {
		let directory = test_directory();
		assert_eq!(load_project_path(&directory.join("last-project.json")), None);
		let _ = std::fs::remove_dir_all(directory);
	}

	#[test]
	fn saved_valid_project_is_restored_and_manual_selection_replaces_saved_path() {
		let directory = test_directory();
		let settings = directory.join("config").join("last-project.json");
		let first = directory.join("first-project");
		let second = directory.join("second-project");
		std::fs::create_dir_all(&first).unwrap();
		std::fs::create_dir_all(&second).unwrap();
		let selected = node_compatible_path(&first.canonicalize().unwrap());
		let current = node_compatible_path(&first.canonicalize().unwrap());
		#[cfg(windows)]
		assert_ne!(selected.canonicalize().unwrap(), current, "the picker normalization must be accounted for when checking Windows paths");
		assert_eq!(canonical_project_path(&selected).unwrap(), canonical_project_path(&current).unwrap(), "the picker path must still match the host's stored path after canonicalization");
		persist_selected_project(&settings, &selected, &current).unwrap();
		assert_eq!(load_project_path(&settings), Some(first.canonicalize().unwrap()));
		assert!(persist_selected_project(&settings, &second, &first).is_err(), "a stale project request must not replace the active path");
		assert_eq!(load_project_path(&settings), Some(first.canonicalize().unwrap()));
		persist_selected_project(&settings, &second, &second).unwrap();
		assert_eq!(load_project_path(&settings), Some(second.canonicalize().unwrap()));
		let _ = std::fs::remove_dir_all(directory);
	}

	#[test]
	fn missing_saved_project_is_cleared_and_falls_back_to_no_project() {
		let directory = test_directory();
		let settings = directory.join("last-project.json");
		let missing = directory.join("project-that-no-longer-exists");
		save_project_path(&settings, &missing).unwrap();
		assert_eq!(load_project_path(&settings), None);
		assert!(!settings.exists(), "stale project path is removed");
		let _ = std::fs::remove_dir_all(directory);
	}

	#[test]
	fn clearing_project_session_removes_the_saved_path() {
		let directory = test_directory();
		let settings = directory.join("last-project.json");
		let project = directory.join("project");
		std::fs::create_dir_all(&project).unwrap();
		save_project_path(&settings, &project.canonicalize().unwrap()).unwrap();
		clear_saved_project(&settings);
		assert_eq!(load_project_path(&settings), None);
		let _ = std::fs::remove_dir_all(directory);
	}

    #[test]
    fn node_binary_defaults_when_environment_variable_is_unset() {
        assert_eq!(resolve_node_binary(None), OsString::from("node"));
    }

    #[test]
    fn node_binary_defaults_when_environment_variable_is_empty() {
        assert_eq!(
            resolve_node_binary(Some(OsString::new())),
            OsString::from("node")
        );
        assert_eq!(
            resolve_node_binary(Some(OsString::from("  "))),
            OsString::from("node")
        );
    }

    #[test]
    fn node_binary_preserves_an_explicit_executable_path() {
        let configured = OsString::from(r"C:\Node Runtime\node.exe");
        assert_eq!(resolve_node_binary(Some(configured.clone())), configured);
    }

    #[cfg(windows)]
    #[test]
    fn ordinary_windows_absolute_path_is_preserved_without_drive_truncation() {
        let path = Path::new(r"D:\aqiron-vscode\aqiron-security\dist\aqiron-desktop-bridge.js");
        let normalized = node_compatible_path(path);
        assert_eq!(normalized, path);
        assert!(normalized.to_string_lossy().starts_with(r"D:\"));
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_windows_path_becomes_a_node_compatible_absolute_path() {
        let path = Path::new(r"\\?\D:\aqiron-vscode\aqiron-security\dist\aqiron-desktop-bridge.js");
        let normalized = node_compatible_path(path);
        assert_eq!(
            normalized,
            Path::new(r"D:\aqiron-vscode\aqiron-security\dist\aqiron-desktop-bridge.js")
        );
        assert!(normalized.to_string_lossy().starts_with(r"D:\"));
        assert!(!normalized.to_string_lossy().starts_with(r"\\?\"));
    }

    #[cfg(windows)]
    #[test]
    fn bridge_script_path_with_spaces_remains_one_command_argument() {
        let bridge = Path::new(r"D:\Aqiron Workspace\dist\aqiron-desktop-bridge.js");
        let root = Path::new(r"D:\Aqiron Workspace");
        let runtime = root.join(r"dist\core-runtime.js");
        let command = desktop_bridge_command(OsStr::new("node"), bridge, root, &runtime);
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(arguments, vec![bridge.as_os_str()]);
        assert_eq!(command.get_program(), OsStr::new("node"));
    }
}

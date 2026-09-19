# Semgrep Configuration Reference - Flutter Security Scanner

## Problem Fixed
❌ **Before**: `semgrep scan --config p/dart` → HTTP 404 (p/dart doesn't exist)
✅ **After**: `semgrep scan --config p/default` → Works correctly

## Valid Semgrep Configurations

### Option 1: Default Rule Pack (Recommended)
```bash
semgrep scan --config p/default .
```
- **Includes**: All default Semgrep rules for major languages (including Dart)
- **Best for**: General-purpose scanning across polyglot projects
- **Performance**: Fast (~2-5 min for medium projects)

### Option 2: Auto-Detection
```bash
semgrep scan --config auto .
```
- **Includes**: Automatically detects project languages and applies relevant rules
- **Best for**: Projects with unknown or mixed dependencies
- **Performance**: Medium speed

### Option 3: Language-Specific Packs
```bash
# For Flutter/Dart projects:
semgrep scan --config p/default --config p/secrets .

# For Android projects:
semgrep scan --config p/java --config p/kotlin --config p/secrets .

# For multiple platforms:
semgrep scan \
  --config p/default \
  --config p/java \
  --config p/kotlin \
  --config p/secrets \
  .
```

### Option 4: With Custom Exclusions
```bash
semgrep scan --config p/default \
  --exclude build \
  --exclude .dart_tool \
  --exclude .gradle \
  --exclude android/build \
  --exclude ios/build \
  --exclude windows/flutter/ephemeral \
  --exclude linux/flutter/ephemeral \
  --exclude macos/Flutter/ephemeral \
  --exclude node_modules \
  --exclude .idea \
  .
```

### Option 5: With JSON Output for Integration
```bash
semgrep scan --config p/default \
  --json \
  --sarif-output semgrep.sarif \
  .
```

## Invalid Configurations (Do NOT Use)

❌ `semgrep scan --config p/dart` - Rule pack doesn't exist  
❌ `semgrep scan --config p/flutter` - Not available  
❌ `semgrep scan --config p/dart/secrets` - Invalid path  

## Troubleshooting

### Issue: "Failed to download configuration... HTTP 404"
**Solution**: Use `p/default` or `auto` instead of `p/dart`

### Issue: Timeout scanning large projects
**Solution**: Add file/folder exclusions or increase timeout

### Issue: Too many false positives
**Solution**: 
1. Use `--config p/owasp-top-ten` for focused rules
2. Use `--exclude` to skip irrelevant folders
3. Create `.semgrep.yml` for custom filtering

### Issue: Want custom rules
**Solution**: Create `.semgrep/.semgrep-custom.yml` and include:
```bash
semgrep scan --config p/default --config .semgrep .
```

## Integration with Aqiron Security Platform

The platform automatically applies these exclusions:
```
build/
.dart_tool/
.gradle/
.aqiron/
android/build/
ios/build/
windows/flutter/ephemeral/
linux/flutter/ephemeral/
macos/Flutter/ephemeral/
node_modules/
.idea/
.vscode/
```

### Scan Modes

1. **SOURCE_CODE Mode** (Aqiron default)
   - Uses: `semgrep scan --config p/default --config p/secrets`
   - Scans: Only developer-written source code
   - Excludes: All build/generated/cache directories

2. **ARTIFACT_BINARY Mode**
   - Uses: YARA, Trivy, MobSF (not Semgrep)
   - Scans: .apk, .aar, .dex, .jar, .so, .dll, .exe
   - Excludes: Source code

3. **ALL Mode**
   - Runs both modes sequentially
   - Provides comprehensive coverage

## CLI Command Template

```bash
# Full Semgrep command with all best practices
semgrep scan \
  --config p/default \
  --config p/secrets \
  --json \
  --sarif-output .aqiron/semgrep.sarif \
  --exclude build \
  --exclude .dart_tool \
  --exclude .gradle \
  --exclude android/build \
  --exclude ios/build \
  --exclude windows/flutter/ephemeral \
  --exclude linux/flutter/ephemeral \
  --exclude macos/Flutter/ephemeral \
  --exclude node_modules \
  --exclude .idea \
  --exclude .vscode \
  --timeout 30 \
  .
```

## Output Interpretation

### Success
```json
{
  "results": [
    {
      "check_id": "rules.python.insecure-sql-query",
      "path": "src/database.py",
      "start": {"line": 42, "col": 1},
      "extra": {
        "message": "Potential SQL injection detected",
        "severity": "HIGH"
      }
    }
  ],
  "errors": []
}
```

### Expected Errors (Non-Fatal)
- Missing files in excluded directories (ignored)
- Timeouts on very large files (skipped)
- Unsupported file types (skipped)

### Critical Errors (Fatal)
- HTTP 404 for config (check config name)
- Permission denied (check file access)
- Semgrep binary not found (install Semgrep)

## Performance Tips

1. **Skip large binary directories**
   ```bash
   --exclude build --exclude .gradle
   ```

2. **Use timeout for large projects**
   ```bash
   --timeout 30  # 30 seconds per file
   ```

3. **Run in specific directory**
   ```bash
   semgrep scan --config p/default src/  # Only scan src/
   ```

4. **Exclude node_modules** (always!)
   ```bash
   --exclude node_modules
   ```

## Configuration Files

### Global Semgrep Config (`.semgrep.yml`)
```yaml
rules:
  - id: custom-rule
    pattern: |
      ...
    severity: HIGH
    message: Custom security finding
```

### Aqiron Platform Config
Platform automatically manages:
- Rule selection (p/default + p/secrets)
- Exclusion patterns (Flutter/Android specifics)
- Output format (JSON + SARIF)
- Timeout handling (120 seconds per tool)

## Further Reading

- Semgrep Official: https://semgrep.dev/docs/
- Rule Registry: https://semgrep.dev/r
- CLI Reference: https://semgrep.dev/docs/cli-reference/

import { RegexSignal } from './types';

const codeExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.kt', '.go', '.rs', '.dart', '.json', '.yaml', '.yml', '.env', '.gradle'];
const configExtensions = [...codeExtensions, '.xml', '.rules', '.toml'];

function signal(input: Omit<RegexSignal, 'falsePositiveGuidance'> & { falsePositiveGuidance?: string }): RegexSignal {
	return {
		falsePositiveGuidance: 'Prefer SDK imports, assignments, or executable configuration over comments and documentation.',
		...input,
	};
}

export const databaseSignals: RegexSignal[] = [
	signal({ id: 'database.postgresql', category: 'database', provider: 'PostgreSQL', pattern: '\\b(?:postgres(?:ql)?|pg(?:_pool)?)\\b|postgres(?:ql)?://', extensions: configExtensions, confidence: 'High', description: 'PostgreSQL client, connection string, or configuration.' }),
	signal({ id: 'database.mongodb', category: 'database', provider: 'MongoDB', pattern: '\\bmongodb(?:\\+srv)?://|\\b(?:mongoose|mongodb)\\b', extensions: codeExtensions, confidence: 'High', description: 'MongoDB connection string or SDK usage.' }),
	signal({ id: 'database.dynamodb', category: 'database', provider: 'DynamoDB', pattern: '\\b(?:DynamoDBClient|DynamoDBDocumentClient|@aws-sdk/lib-dynamodb|dynamodb\\.)', extensions: codeExtensions, confidence: 'High', description: 'DynamoDB SDK usage.' }),
	signal({ id: 'database.supabase', category: 'database', provider: 'Supabase', pattern: '\\b(?:supabase\\.co|createClient\\s*\\(|@supabase/)', extensions: codeExtensions, confidence: 'High', description: 'Supabase client or project endpoint.' }),
	signal({ id: 'database.firebase', category: 'database', provider: 'Firebase', pattern: '\\b(?:firebaseio\\.com|firebasedatabase\\.app|firebase\\.|@firebase/|firebase-admin)', extensions: configExtensions, confidence: 'High', description: 'Firebase SDK, project endpoint, or configuration.' }),
];

export const paymentSignals: RegexSignal[] = [
	signal({ id: 'payment.stripe', category: 'payment', provider: 'Stripe', pattern: '\\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\\b|\\b(?:stripe|StripeClient|@stripe/)', extensions: codeExtensions, confidence: 'High', description: 'Stripe SDK or key-shaped value.' }),
	signal({ id: 'payment.paypal', category: 'payment', provider: 'PayPal', pattern: '\\b(?:paypal|PayPalHttpClient|@paypal/|api-m\\.paypal\\.com)\\b', extensions: codeExtensions, confidence: 'High', description: 'PayPal SDK or API endpoint.' }),
	signal({ id: 'payment.braintree', category: 'payment', provider: 'Braintree', pattern: '\\b(?:braintree|BraintreeGateway|braintreegateway\\.com)\\b', extensions: codeExtensions, confidence: 'High', description: 'Braintree SDK or gateway usage.' }),
];

export const llmSignals: RegexSignal[] = [
	signal({ id: 'llm.openai', category: 'llm', provider: 'OpenAI', pattern: '\\b(?:api\\.openai\\.com|OpenAI\\s*\\(|openai\\.|openai-node)\\b|sk-[A-Za-z0-9_-]{20,}', extensions: codeExtensions, confidence: 'High', description: 'OpenAI SDK, endpoint, or key-shaped value.' }),
	signal({ id: 'llm.anthropic', category: 'llm', provider: 'Anthropic', pattern: '\\b(?:api\\.anthropic\\.com|Anthropic\\s*\\(|@anthropic-ai|anthropic\\.)\\b|sk-ant-[A-Za-z0-9_-]{20,}', extensions: codeExtensions, confidence: 'High', description: 'Anthropic SDK, endpoint, or key-shaped value.' }),
	signal({ id: 'llm.gemini', category: 'llm', provider: 'Gemini', pattern: '\\b(?:generativelanguage\\.googleapis\\.com|GoogleGenerativeAI|@google/generative-ai|gemini)\\b', extensions: codeExtensions, confidence: 'High', description: 'Gemini SDK or API endpoint.' }),
];

export const secretSignals: RegexSignal[] = [
	signal({ id: 'secret.api-key', category: 'secret', provider: 'Generic API key', pattern: '\\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\\b\\s*[:=]\\s*["\']?[A-Za-z0-9_./+=-]{16,}', extensions: configExtensions, confidence: 'Medium', description: 'Named API key or token assignment.' }),
	signal({ id: 'secret.bearer-token', category: 'secret', provider: 'Bearer token', pattern: '\\bBearer\\s+[A-Za-z0-9._~+/=-]{20,}', extensions: codeExtensions, confidence: 'High', description: 'Bearer token in an executable request.' }),
	signal({ id: 'secret.password', category: 'secret', provider: 'Password', pattern: '\\b(?:password|passwd|pwd)\\b\\s*[:=]\\s*["\'][^"\']{8,}["\']', extensions: configExtensions, confidence: 'Medium', description: 'Hard-coded password assignment.' }),
	signal({ id: 'secret.private-key', category: 'secret', provider: 'Private key', pattern: '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', extensions: configExtensions, confidence: 'High', description: 'PEM private key material.' }),
	signal({ id: 'secret.aws-credential', category: 'secret', provider: 'AWS', pattern: '\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b|aws_secret_access_key\\s*[:=]', extensions: configExtensions, confidence: 'High', description: 'AWS access key or secret credential.' }),
	signal({ id: 'secret.cloud-credential', category: 'secret', provider: 'Cloud credential', pattern: '\\b(?:GOOG[A-Z0-9_-]{20,}|AIza[A-Za-z0-9_-]{20,}|AZURE_CLIENT_SECRET)\\b', extensions: configExtensions, confidence: 'Medium', description: 'Google or Azure credential-shaped value.' }),
];

export const endpointSignals: RegexSignal[] = [
	signal({ id: 'endpoint.rest', category: 'endpoint', provider: 'REST', pattern: '\\bhttps?://[^\\s"\'<>]+|\\b(?:fetch|axios|got|request)\\s*\\(', extensions: codeExtensions, confidence: 'Medium', description: 'HTTP endpoint or REST client usage.' }),
	signal({ id: 'endpoint.graphql', category: 'endpoint', provider: 'GraphQL', pattern: '\\b(?:graphql|GraphQLClient|ApolloClient|urql|/graphql)\\b', extensions: codeExtensions, confidence: 'High', description: 'GraphQL client, endpoint, or query integration.' }),
];

export const serviceSignals: RegexSignal[] = [...paymentSignals, ...llmSignals];
export const builtInRegexSignals: RegexSignal[] = [...databaseSignals, ...paymentSignals, ...llmSignals, ...secretSignals, ...endpointSignals];

import * as assert from 'assert';
import { providerCredentialFallbackName } from '../ai/services/providerCredentialName';
import { configuredProviderOptions } from '../webview/ui/providerOptions';

suite('Provider UI helpers', () => {
	test('only returns providers with saved credentials', () => {
		const providers = configuredProviderOptions([
			{ id: 'openai-key', name: 'OpenAI API key ••••1234', providerId: 'openai', last4: '1234', createdAt: 'now', updatedAt: 'now' },
		]);
		assert.deepStrictEqual(providers.map((provider) => provider.id), ['openai']);
		assert.deepStrictEqual(configuredProviderOptions([]), []);
	});

	test('uses provider-specific masked fallback credential labels', () => {
		assert.strictEqual(providerCredentialFallbackName('openai', '1234'), 'OpenAI API key ••••1234');
		assert.strictEqual(providerCredentialFallbackName('claude', '5678'), 'Claude API key ••••5678');
		assert.strictEqual(providerCredentialFallbackName('gemini', '9012'), 'Gemini API key ••••9012');
		assert.strictEqual(providerCredentialFallbackName('openrouter', '3456'), 'OpenRouter API key ••••3456');
	});
});

<?php declare(strict_types=1);

namespace Bref\Secrets\Test;

use AsyncAws\Core\Test\ResultMockFactory;
use AsyncAws\Ssm\Result\GetParametersResult;
use AsyncAws\Ssm\SsmClient;
use AsyncAws\Ssm\ValueObject\Parameter;
use Bref\Secrets\Secrets;
use PHPUnit\Framework\TestCase;

class SecretsTest extends TestCase
{
    private array $resultParams = [
        'Name' => '/some/parameter',
        'Value' => 'foobar',
    ];

    /** @var string Temporary directory used as the dotenv layer root */
    private string $dotEnvDir;

    public function setUp(): void
    {
        if (file_exists(sys_get_temp_dir() . '/bref-ssm-parameters.php')) {
            unlink(sys_get_temp_dir() . '/bref-ssm-parameters.php');
        }

        // Point the loader at a writable temp directory instead of /opt/secrets
        $this->dotEnvDir = sys_get_temp_dir() . '/bref-test-secrets';
        @mkdir($this->dotEnvDir, 0700, true);
        Secrets::$dotEnvDirectory = $this->dotEnvDir;
    }

    public function tearDown(): void
    {
        // Remove any env files created during the test
        foreach (glob($this->dotEnvDir . '/env.*') ?: [] as $file) {
            unlink($file);
        }

        // Reset to the real layer path
        Secrets::$dotEnvDirectory = '/opt/secrets';

        // Clean up stage-detection env vars
        putenv('STAGE');
        putenv('APP_ENV');

        // Clean up any env vars that still hold a bref-ssm: reference (e.g. leaked
        // from a test that threw before reaching its own cleanup block)
        $envVars = getenv() ?: [];
        foreach ($envVars as $key => $value) {
            if (str_starts_with((string) $value, 'bref-ssm:')) {
                putenv($key);
                unset($_ENV[$key], $_SERVER[$key]);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Original SSM tests
    // -------------------------------------------------------------------------

    public function test_decrypts_env_variables(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');
        putenv('SOME_OTHER_VARIABLE=helloworld');

        // Sanity checks
        $this->assertSame('bref-ssm:/some/parameter', getenv('SOME_VARIABLE'));
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        $ssmClient = $this->mockSsmClient([new Parameter($this->resultParams)]);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));
        $this->assertSame('foobar', $_SERVER['SOME_VARIABLE']);
        $this->assertSame('foobar', $_ENV['SOME_VARIABLE']);
        // Check that the other variable was not modified
        $this->assertSame('helloworld', getenv('SOME_OTHER_VARIABLE'));

        // Cleanup
        putenv('SOME_VARIABLE');
        putenv('SOME_OTHER_VARIABLE');
    }

    public function test_caches_parameters_to_call_SSM_only_once(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/some/parameter');

        // Call twice, the mock will assert that SSM was only called once
        $ssmClient = $this->mockSsmClient([new Parameter($this->resultParams)]);
        Secrets::loadSecretEnvironmentVariables($ssmClient);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('SOME_VARIABLE'));

        // Cleanup
        putenv('SOME_VARIABLE');
    }

    public function test_same_ssm_value_can_be_assigned_more_than_once(): void
    {
        putenv('VAR1=bref-ssm:/some/parameter');
        putenv('VAR2=bref-ssm:/some/parameter');

        // Sanity checks
        $this->assertSame('bref-ssm:/some/parameter', getenv('VAR1'));
        $this->assertSame('bref-ssm:/some/parameter', getenv('VAR2'));

        $ssmClient = $this->mockSsmClient([
            new Parameter($this->resultParams),
            new Parameter($this->resultParams),
        ]);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('VAR1'));
        $this->assertSame('foobar', getenv('VAR2'));

        // Cleanup
        putenv('VAR1');
        putenv('VAR2');
    }

    public function test_throws_a_clear_error_message_on_missing_permissions(): void
    {
        putenv('SOME_VARIABLE=bref-ssm:/app/test');

        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->getMock();
        $result = ResultMockFactory::createFailing(GetParametersResult::class, 400, 'User: arn:aws:sts::123456:assumed-role/app-dev-us-east-1-lambdaRole/app-dev-hello is not authorized to perform: ssm:GetParameters on resource: arn:aws:ssm:us-east-1:123456:parameter/app/test because no identity-based policy allows the ssm:GetParameters action');
        $ssmClient->method('getParameters')
            ->willReturn($result);

        $expected = preg_quote("Bref was not able to resolve secrets contained in environment variables from SSM because of a permissions issue with the SSM API. Did you add IAM permissions in serverless.yml to allow Lambda to access SSM? (docs: https://bref.sh/docs/environment/variables.html#at-deployment-time).\nFull exception message:", '/');
        $this->expectExceptionMessageMatches("/$expected .+/");
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        // Cleanup
        putenv('SOME_VARIABLE');
    }

    // -------------------------------------------------------------------------
    // dotenv layer tests
    // -------------------------------------------------------------------------

    public function test_loads_env_vars_from_dotenv_layer_file(): void
    {
        putenv('STAGE=production');
        file_put_contents($this->dotEnvDir . '/env.production', "APP_KEY=secret123\nDB_HOST=localhost\n");

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClientNotCalled());

        $this->assertSame('secret123', getenv('APP_KEY'));
        $this->assertSame('secret123', $_ENV['APP_KEY']);
        $this->assertSame('secret123', $_SERVER['APP_KEY']);
        $this->assertSame('localhost', getenv('DB_HOST'));

        // Cleanup
        putenv('APP_KEY');
        putenv('DB_HOST');
    }

    public function test_dotenv_file_does_not_overwrite_existing_env_vars(): void
    {
        putenv('STAGE=production');
        putenv('APP_KEY=already-set');
        file_put_contents($this->dotEnvDir . '/env.production', "APP_KEY=from-file\n");

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClientNotCalled());

        $this->assertSame('already-set', getenv('APP_KEY'));

        // Cleanup
        putenv('APP_KEY');
    }

    public function test_resolves_bref_ssm_references_defined_in_dotenv_file(): void
    {
        putenv('STAGE=production');
        file_put_contents($this->dotEnvDir . '/env.production', "DB_PASSWORD=bref-ssm:/some/parameter\n");

        $ssmClient = $this->mockSsmClient([new Parameter($this->resultParams)]);
        Secrets::loadSecretEnvironmentVariables($ssmClient);

        $this->assertSame('foobar', getenv('DB_PASSWORD'));
        $this->assertSame('foobar', $_ENV['DB_PASSWORD']);
        $this->assertSame('foobar', $_SERVER['DB_PASSWORD']);

        // Cleanup
        putenv('DB_PASSWORD');
    }

    public function test_silently_skips_when_dotenv_file_does_not_exist(): void
    {
        putenv('STAGE=production');
        // No file created — should not throw

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClientNotCalled());

        $this->assertTrue(true); // reached without exception
    }

    public function test_resolves_stage_from_STAGE_env_var(): void
    {
        putenv('STAGE=staging');
        file_put_contents($this->dotEnvDir . '/env.staging', "STAGE_VAR=from-staging\n");

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClientNotCalled());

        $this->assertSame('from-staging', getenv('STAGE_VAR'));

        // Cleanup
        putenv('STAGE_VAR');
    }

    public function test_falls_back_to_APP_ENV_when_STAGE_is_not_set(): void
    {
        putenv('STAGE'); // unset
        putenv('APP_ENV=dev');
        file_put_contents($this->dotEnvDir . '/env.dev', "APP_ENV_VAR=from-dev\n");

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClientNotCalled());

        $this->assertSame('from-dev', getenv('APP_ENV_VAR'));

        // Cleanup
        putenv('APP_ENV_VAR');
    }

    public function test_falls_back_to_production_when_no_stage_env_var_is_set(): void
    {
        putenv('STAGE'); // unset
        putenv('APP_ENV'); // unset
        file_put_contents($this->dotEnvDir . '/env.production', "PROD_VAR=from-production\n");

        Secrets::loadSecretEnvironmentVariables($this->mockSsmClientNotCalled());

        $this->assertSame('from-production', getenv('PROD_VAR'));

        // Cleanup
        putenv('PROD_VAR');
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * @param array<Parameter> $resultParameters
     */
    private function mockSsmClient(array $resultParameters): SsmClient
    {
        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getParameters'])
            ->getMock();

        $result = ResultMockFactory::create(GetParametersResult::class, [
            'Parameters' => $resultParameters,
        ]);

        $expectedNames = [];
        foreach ($resultParameters as $resultParameter) {
            $expectedNames[] = $resultParameter->getName();
        }
        $ssmClient->expects($this->once())
            ->method('getParameters')
            ->with([
                'Names' => $expectedNames,
                'WithDecryption' => true,
            ])
            ->willReturn($result);

        return $ssmClient;
    }

    /**
     * Returns a mock SSM client that asserts getParameters is never called.
     */
    private function mockSsmClientNotCalled(): SsmClient
    {
        $ssmClient = $this->getMockBuilder(SsmClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getParameters'])
            ->getMock();

        $ssmClient->expects($this->never())
            ->method('getParameters');

        return $ssmClient;
    }
}

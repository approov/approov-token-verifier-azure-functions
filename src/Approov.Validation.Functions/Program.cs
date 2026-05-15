using Approov.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(services =>
    {
        services
            .AddSingleton(ApproovValidationOptionsFactory.FromEnvironment())
            .AddSingleton<ApproovMessageSignatureVerifier>()
            .AddSingleton<ApproovRequestValidator>();
    })
    .Build();

host.Run();

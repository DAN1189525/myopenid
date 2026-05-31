using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Client;

namespace WeClientDD;

public class Minivovo:IHostedService
{
    public readonly IServiceProvider  ServiceProvider;
    private readonly
      IOptionsMonitor<OpenIddictClientOptions>
      _options;

    public Minivovo(IServiceProvider serviceProvider, IOptionsMonitor<OpenIddictClientOptions> options)
    {
        ServiceProvider = serviceProvider;
        _options = options;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
       await  using var scope = ServiceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<MyDb>();
        await context.Database.EnsureCreatedAsync(cancellationToken);//数据库存在则删除
         }


    public Task StopAsync(CancellationToken cancellationToken)
    {
        return  Task.CompletedTask;
    }
}
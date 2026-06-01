using OpenIddict.Abstractions;

namespace WebServiceDD;

public class Minivovo:IHostedService
{
    public readonly IServiceProvider  ServiceProvider;

    public Minivovo(IServiceProvider serviceProvider)
    {
        ServiceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
       await  using var scope = ServiceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<DBUser>();
       await  context.Database.EnsureCreatedAsync();//数据库存在则删除

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var men = await manager.FindByClientIdAsync("mvc");
        //if (men != null) {
        //   await manager.DeleteAsync(men);
        //}
        if (men is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mvc",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",

                RedirectUris =
        {
            new Uri("https://localhost:7213/callback/login/local")
        },

                PostLogoutRedirectUris =
        {
            new Uri("https://localhost:7213/callback/logout/local")
        },

                Permissions =
        {
            OpenIddictConstants.Permissions.Endpoints.Authorization,
            OpenIddictConstants.Permissions.Endpoints.Token,

            OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
            OpenIddictConstants.Permissions.ResponseTypes.Code,

            OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
            OpenIddictConstants.Permissions.Prefixes.Scope + "profile"
        }
            });
            
        }
        var socpeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var scopeapi = await socpeManager.FindByNameAsync("profile");
        if (scopeapi == null)
        {
           await socpeManager.CreateAsync( new OpenIddictScopeDescriptor
            {
                Name = "profile",
                DisplayName = "API Access",
                Resources = { "email", "profile", "roles" }
            });
            }

    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return  Task.CompletedTask;
    }
}
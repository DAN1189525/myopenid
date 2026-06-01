using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using WebServiceDD;
using WebServiceDD.Models;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddDbContext<DBUser>(option =>
{
    option.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    option.UseOpenIddict();
});
builder.Services.AddHostedService<Minivovo>();
//     Ĭ    ֤      ʹ   OpenIddict     ֤       
builder.Services.AddIdentity<Appuser, AppRole>()
    .AddEntityFrameworkStores<DBUser>()
    .AddDefaultTokenProviders().AddDefaultUI();//  
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore() //  
               .UseDbContext<DBUser>()
               ;
    })
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();

        options.UseAspNetCore()
            .EnableStatusCodePagesIntegration()// ʹ 
            .EnableRedirectionEndpointPassthrough(); //      
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();
        options.UseSystemNetHttp()
            .SetProductInformation(typeof(Program).Assembly); // ʹ  


        options.UseWebProviders()
            .AddGitHub(options =>
            {
                options.SetClientId("c4ade52327b01ddacff3")
                    .SetClientSecret("da6bed851b75e317bf6b2cb67013679d9467c122")
                    .SetRedirectUri("callback/login/github");
            })
            ;

    })
    .AddServer(options =>
    {
        options.AllowAuthorizationCodeFlow();
        //    ö˵ 
        options.SetTokenEndpointUris("/connect/token")
        .SetUserInfoEndpointUris("/connect/userinfo")
        .SetAuthorizationEndpointUris("/connect/authorize")//setAuthorizationEndpointUris("/connect/authorize") 
        .SetEndSessionEndpointUris("/connect/logout");//setEndSessionEndpointUris("/connect/logout") 

        options.RegisterScopes(OpenIddictConstants.Permissions.Scopes.Email, OpenIddictConstants.Permissions.Scopes.Roles, OpenIddictConstants.Permissions.Scopes.Profile,
             OpenIddictConstants.Scopes.OpenId); //        


        options.AddDevelopmentEncryptionCertificate()
       .AddDevelopmentSigningCertificate();//      


        options.UseAspNetCore()
               .EnableStatusCodePagesIntegration()// ʹ 
               .EnableAuthorizationEndpointPassthrough()// 
               .EnableTokenEndpointPassthrough() // 
               .EnableTokenEndpointPassthrough()// 
               .EnableEndSessionEndpointPassthrough();//  

    })
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore() //  
               .UseDbContext<DBUser>();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
app.MapControllers();
app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();



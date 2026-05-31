using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using WeClientDD;
using static OpenIddict.Abstractions.OpenIddictConstants.Permissions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddDbContext<MyDb>(option =>
{
    option.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    option.UseOpenIddict();
});

builder.Services.AddAuthentication(o =>
{
    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
    .AddCookie(o =>
    {
        o.LoginPath = "/login";
        o.LogoutPath = "/outlogin";
        o.ExpireTimeSpan = TimeSpan.FromMinutes(50);
        o.SlidingExpiration=false;
    });


builder.Services.AddOpenIddict()
    .AddCore(o =>
{
    o.UseEntityFrameworkCore()
        .UseDbContext<MyDb>();
})
    .AddClient(o =>
{
    o.AllowAuthorizationCodeFlow();


    o.AddDevelopmentEncryptionCertificate();
    o.AddDevelopmentSigningCertificate();

    o.UseAspNetCore()
    .EnableRedirectionEndpointPassthrough()
    .EnablePostLogoutRedirectionEndpointPassthrough()
    .EnableStatusCodePagesIntegration();

    o.UseSystemNetHttp().SetProductInformation(typeof(Program).Assembly);

    o.AddRegistration(new OpenIddict.Client.OpenIddictClientRegistration
    {
        Issuer =new Uri("https://localhost:7210/", UriKind.Absolute),
        ClientId="mvc",
        ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
        Scopes = {OpenIddictConstants.Scopes.Profile,OpenIddictConstants.Scopes.OpenId},
        RedirectUri=new Uri("callback/login/local", UriKind.Relative),
        PostLogoutRedirectUri=new Uri("callback/logout/local", UriKind.Relative)
        
    });
    
});
builder.Services.AddHttpClient();
builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();
builder.Services.AddHostedService<Minivovo>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Authencation}/{action=Index}");

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();

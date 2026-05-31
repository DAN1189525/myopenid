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
// ����Ĭ����֤������ʹ�� OpenIddict ����֤�������
builder.Services.AddIdentity<Appuser, AppRole>()
    .AddEntityFrameworkStores<DBUser>()
    .AddDefaultTokenProviders().AddDefaultUI();// ��� ASP.NET Core Identity �������� EF Core �洢
// ���� OpenIddict��Core (EF Core �洢) + Server (token endpoint ��) + Validation (���ط�������֤)
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        // ʹ�� EF Core �洢��ָ�� DbContext
        options.UseEntityFrameworkCore() // ����չ������Ҫ using OpenIddict.EntityFrameworkCore;
               .UseDbContext<DBUser>()
               ;
    })
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();

        options.UseAspNetCore()
            .EnableStatusCodePagesIntegration()// ʹ OpenIddict �Ĵ�����Ӧ������ȷ�� HTTP ״̬��
            .EnableRedirectionEndpointPassthrough(); // ������Ȩ�������ض���˵�ֱ�Ӵ��ݵ� ASP.NET Core �ܵ����Ա� Razor Pages ���Դ�������
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();
        options.UseSystemNetHttp()
            .SetProductInformation(typeof(Program).Assembly); // ʹ�� System.Net.Http ���� HTTP ���󣬲����� User-Agent ��Ϣ
        
        
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
        // ���ö˵�
        options.SetTokenEndpointUris("/connect/token")//�����Ҫ���ƶ˵�
        .SetUserInfoEndpointUris("/connect/userinfo")//�����Ҫ�û���Ϣ�˵�
        .SetAuthorizationEndpointUris("/connect/authorize")//setAuthorizationEndpointUris("/connect/authorize") // �����Ҫ��Ȩ�˵�
        .SetEndSessionEndpointUris("/connect/logout");//setEndSessionEndpointUris("/connect/logout") // �����Ҫע���˵�

        options.RegisterScopes(OpenIddictConstants.Permissions.Scopes.Email, OpenIddictConstants.Permissions.Scopes.Roles,OpenIddictConstants.Permissions.Scopes.Profile); // ע����Ҫ��������

         // �����Ҫ��Ȩ����

        options.AddDevelopmentEncryptionCertificate()
       .AddDevelopmentSigningCertificate();// ��������ʱ֤�飬������ʹ�ó־�֤��


        options.UseAspNetCore()
               .EnableStatusCodePagesIntegration()// ʹ OpenIddict �Ĵ�����Ӧ������ȷ�� HTTP ״̬��
               .EnableAuthorizationEndpointPassthrough()// ������Ȩ��������Ȩ�˵�ֱ�Ӵ��ݵ� ASP.NET Core �ܵ����Ա� Razor Pages ���Դ�������
               .EnableTokenEndpointPassthrough() // �������ƶ˵�ֱ�Ӵ��ݵ� ASP.NET Core �ܵ����Ա� Razor Pages ���Դ�������
               .EnableTokenEndpointPassthrough()// �������ƶ˵�ֱ�Ӵ��ݵ� ASP.NET Core �ܵ����Ա� Razor Pages ���Դ�������
               .EnableEndSessionEndpointPassthrough();// ����ע���˵�ֱ�Ӵ��ݵ� ASP.NET Core �ܵ����Ա� Razor Pages ���Դ�������

    })
    .AddCore(options => { 
        // ʹ�� EF Core �洢��ָ�� DbContext
        options.UseEntityFrameworkCore() // ����չ������Ҫ using OpenIddict.EntityFrameworkCore;
               .UseDbContext<DBUser>();
    })
    .AddValidation(options =>
    {
        // ʹ�ñ��ط��������� token ��֤
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

app.UseHttpsRedirection();

app.UseRouting();

// ������������֤�м������������Ȩ
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();



using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace WeClientDD.Controllers
{
    public class AuthenticationController : Controller
    {
        [HttpGet("/")]
        public ActionResult Index()
        {
            return View();
        }


        [HttpGet("~/login")]
        public IActionResult Login(string returnUrl)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
            };
            return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/callback/login/{provider}")]
        [HttpPost("~/callback/login/{provider}")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> LogInCallback()
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);//获取server端的认证结果
            if (result is not { Succeeded: true, Principal.Identity.IsAuthenticated: true })//如果认证失败或者没有认证成功
            {
                throw new InvalidOperationException("External authentication error");
            }
            var identity = new ClaimsIdentity(authenticationType: "cookie", nameType: ClaimTypes.Name, roleType: ClaimTypes.Role);//创建一个新的ClaimsIdentity对象，指定认证类型为"cookie"，
                                                                                                                                  //名称类型为ClaimTypes.Name，角色类型为ClaimTypes.Role
            identity.SetClaim(ClaimTypes.Email, result.Principal.GetClaim(ClaimTypes.Email));
            identity.SetClaim(ClaimTypes.Name, result.Principal.GetClaim(ClaimTypes.Name));
            identity.SetClaim(ClaimTypes.NameIdentifier, result.Principal.GetClaim(ClaimTypes.NameIdentifier));
            identity.SetClaim(Claims.Private.RegistrationId, result.Principal.GetClaim(Claims.Private.RegistrationId));
            identity.SetClaim(Claims.Private.ProviderName, result.Principal.GetClaim(Claims.Private.ProviderName));
            var properties = new AuthenticationProperties(result.Properties.Items)//创建一个新的AuthenticationProperties对象，并将从认证结果中获取的属性项传递给它
            {
                RedirectUri = result.Properties.RedirectUri ?? "/",
                IssuedUtc = null,
                ExpiresUtc = null,
                IsPersistent = false
            };

            properties.StoreTokens(result.Properties.GetTokens().Where(x => x.Name is OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken
            or OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken or OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken));//将从认证结果中获取的令牌存储到AuthenticationProperties对象中，
                                                                                                                                                //筛选出名称为BackchannelAccessToken、BackchannelIdentityToken或RefreshToken的令牌

            return SignIn(new ClaimsPrincipal(identity), properties);
        }

        [HttpGet("~/callback/logout/{provider}")]
        [HttpPost("~/callback/logout/{provider}")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> LogoutCallback()
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
            if (result is not { Succeeded: true, Principal.Identity.IsAuthenticated: true })
            {
                throw new InvalidOperationException("External authentication error");
            }
            var properties = new AuthenticationProperties(result.Properties.Items)
            {
                RedirectUri = result.Properties.RedirectUri ?? "/",
                IssuedUtc = null,
                ExpiresUtc = null,
                IsPersistent = false
            };
            return SignOut(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}

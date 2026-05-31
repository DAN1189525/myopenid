using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace WebServiceDD.Controllers
{
    public class AuthenticationController : Controller
    {
        [HttpGet("/callback/login/{provider}")]
        public async Task<IActionResult> LoginCallback()
        {
            //因为从客户端那边跳过来登录的，所以openiddict会自动帮我们处理登录回调，并且在HttpContext中设置好用户的身份信息，所以我们只需要从HttpContext中获取用户的身份信息即可
            var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);// 尝试对当前HTTP上下文进行身份验证，使用OpenIddict客户端ASP.NET Core默认的身份验证方案

            if(result is not { Succeeded: true ,Principal.Identity.IsAuthenticated:true})// 如果身份验证结果不成功或者用户身份未认证，则返回一个BadRequest结果，指示请求无效
            {
                throw new InvalidOperationException("外部登录失败。");// 抛出一个InvalidOperationException异常，指示外部登录失败
            }

            var idntity = new ClaimsIdentity(
                authenticationType: "ExternalLogin",
                nameType:ClaimTypes.Name,
                roleType:ClaimTypes.Role
                );// 创建一个新的ClaimsIdentity对象，指定身份验证类型为"ExternalLogin"，名称类型为ClaimTypes.Name，角色类型为ClaimTypes.Role

            idntity.SetClaim(ClaimTypes.Email, result.Principal.GetClaim(ClaimTypes.Email))// 从身份验证结果的Principal中获取Email声明，并将其设置到新的ClaimsIdentity中
                .SetClaim(ClaimTypes.Name, result.Principal.GetClaim(ClaimTypes.Name))// 从身份验证结果的Principal中获取Name声明，并将其设置到新的ClaimsIdentity中
                .SetClaim(ClaimTypes.NameIdentifier, result.Principal.GetClaim(ClaimTypes.NameIdentifier));// 从身份验证结果的Principal中获取NameIdentifier声明，并将其设置到新的ClaimsIdentity中

            idntity.SetClaim(Claims.Private.RegistrationId,result.Principal.GetClaim(Claims.Private.RegistrationId))// 从身份验证结果的Principal中获取RegistrationId声明，并将其设置到新的ClaimsIdentity中
                .SetClaim(Claims.Private.ProviderName, result.Principal.GetClaim(Claims.Private.ProviderName));// 从身份验证结果的ProviderName中获取Provider声明，并将其设置到新的ClaimsIdentity中


            var properties = new AuthenticationProperties(result.Properties.Items)
            {
                RedirectUri = result.Properties.RedirectUri?? "/",
                IssuedUtc=null,
                ExpiresUtc= null,
                IsPersistent=false
            };
            properties.StoreTokens(result.Properties.GetTokens().Where(token =>
                token.Name is OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken)
        );// 将身份验证结果的属性中的令牌存储到新的AuthenticationProperties对象中
            return SignIn(new ClaimsPrincipal(idntity), properties);// 返回一个SignIn结果，使用新的ClaimsPrincipal和AuthenticationProperties进行登录
        }
    }
}

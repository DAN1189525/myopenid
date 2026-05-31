using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using WebServiceDD.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Collections.Generic;
using System.Security.Claims; // 添加此 using 指令
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using WebServiceDD.AuthenticationViewModel; // 添加此 using 指令

namespace WebServiceDD.Controllers
{
    public class AuthorizationController : Controller
    {
        public readonly IOpenIddictApplicationManager _applicationManager;// 注入OpenIddict应用程序管理器，以便在授权过程中使用
        public readonly IOpenIddictAuthorizationManager _authorizationManager;// 注入OpenIddict授权管理器，以便在授权过程中使用
        public readonly IOpenIddictScopeManager _scopeManager;// 注入OpenIddict范围管理器，以便在授权过程中使用
        public readonly SignInManager<Appuser> _signInManager;// 注入ASP.NET Core Identity的登录管理器，以便在授权过程中使用     
        public readonly UserManager<AppRole> _userManager;// 注入ASP.NET Core Identity的用户管理器，以便在授权过程中使用

        public AuthorizationController(IOpenIddictApplicationManager applicationManager, IOpenIddictAuthorizationManager authorizationManager, IOpenIddictScopeManager scopeManager, SignInManager<Appuser> signInManager, UserManager<AppRole> userManager)
        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpPost("coonect/authorize")]// 处理授权请求的端点
        [IgnoreAntiforgeryToken]// 允许跨站请求伪造（CSRF）攻击，因为授权请求通常来自外部客户端
        public async Task<IActionResult> authorize()
        {
            #region// 获取授权请求并验证用户身份
            var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("无法获取授权请求。");// 从当前HTTP上下文中获取OpenIddict服务器请求对象，如果无法获取则抛出异常

            var result = await HttpContext.AuthenticateAsync();// 尝试对当前HTTP上下文进行身份验证，以确定用户是否已经登录
            if (result is not { Succeeded: true }
                || (request.HasPromptValue(PromptValues.Login))
                || request.MaxAge is 0
                || (request.MaxAge is not null && result.Properties?.IssuedUtc is null && TimeProvider.System.GetUtcNow() - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value) && TempData["IgnoreAuthenticationChallenge"] is null or false))
            // 如果身份验证失败，或者请求中包含登录提示，或者请求的最大年龄为0，或者请求的最大年龄不为null且已过期，并且TempData中没有设置忽略身份验证挑战，则返回一个挑战结果
            {
                if (!request.HasPromptValue(PromptValues.None))// 如果请求中没有包含"none"提示，则返回一个禁止访问结果，指示用户需要登录
                {
                    return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }));// 返回一个禁止访问结果，指示用户需要登录，并且包含错误信息
                }
            }

            TempData["IgnoreAuthenticationChallenge"] = true;// 设置TempData中的"IgnoreAuthenticationChallenge"标志为true，以便在后续请求中忽略身份验证挑战

            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(Request.HasFormContentType ? Request.Form : Request.Query)
            });// 返回一个挑战结果，指示用户需要登录，并且设置重定向URI为当前请求的路径和查询字符串，以便在登录成功后能够正确重定向回授权请求的原始位置

            #endregion
            #region// 获取授权请求、验证用户身份并处理授权逻辑
            var user = await _userManager.GetUserAsync(result.Principal) ??
                throw new InvalidOperationException("The user details cannot be retrieved.");// 从身份验证结果中获取用户对象，如果无法获取则抛出异常

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ?? throw new InvalidOperationException("The application details cannot be retrieved.");
            // 根据请求中的客户端ID从应用程序管理器中获取应用程序对象，如果无法获取则抛出异常

            var authorizationList = new List<object>();
            await foreach (var item in _authorizationManager.FindAsync(
                subject: await _userManager.GetUserIdAsync(user),// 查找授权对象的主体为当前用户的ID
                client: await _applicationManager.GetIdAsync(application),// 查找授权对象的客户端为当前应用程序的ID
                status: Statuses.Valid,// 查找状态为有效的授权对象
                type: AuthorizationTypes.Permanent,// 查找类型为永久的授权对象
                scopes: request.GetScopes()))
            {
                authorizationList.Add(item);
            }// 使用授权管理器的FindAsync方法异步查找符合条件的授权对象，并将它们添加到authorizationList列表中。查找条件包括用户ID、客户端ID、授权状态、授权类型和请求的范围
            // authorizationList 现在包含所有授权对象

            switch (await _applicationManager.GetApplicationTypeAsync(application))
            {
                case ConsentTypes.External when authorizationList.Count is 0:
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizationList.Count is not 0://when起到一个并且的作用
            case ConsentTypes.Explicit when authorizationList.Count is not 0 && !request.HasPromptValue(PromptValues.Consent):
                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens.
                identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                        .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                        .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                        .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
                        .SetClaims(Claims.Role, [.. (await _userManager.GetRolesAsync(user))]);

                // Note: in this sample, the granted scopes match the requested scope
                // but you may want to allow the user to uncheck specific scopes.
                // For that, simply restrict the list of scopes before calling SetScopes.
                identity.SetScopes(request.GetScopes());
                 // 扩展方法在 System.Linq 命名空间下

                var resources = _scopeManager.ListResourcesAsync(identity.GetScopes());
                List<string> cc = new List<string>();
                await  foreach (var bb in resources)
                {
                    cc.Add(bb);
                }
                identity.SetResources(cc);

                // Automatically create a permanent authorization to avoid requiring explicit consent
                // for future authorization or token requests containing the same scopes.
                var authorization = authorizationList.LastOrDefault();
                authorization ??= await _authorizationManager.CreateAsync(
                    identity: identity,
                    subject: await _userManager.GetUserIdAsync(user),
                    client: (await _applicationManager.GetIdAsync(application))!,
                    type: AuthorizationTypes.Permanent,
                    scopes: identity.GetScopes());

                identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(GetDestinations);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit when request.HasPromptValue(PromptValues.None):
            case ConsentTypes.Systematic when request.HasPromptValue(PromptValues.None):
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    }));

            // In every other case, render the consent form.
            default:
                return View(new AuthorizeViewModel
                {
                    ApplicationName = (await _applicationManager.GetLocalizedDisplayNameAsync(application))!,
                    Scope = request.Scope
                });
            }
            
            #endregion

            return View();
        }
        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            switch (claim.Type)
            {
                case Claims.Name or Claims.PreferredUsername:
                    yield return Destinations.AccessToken;

                    if (claim.Subject!.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;

                    if (claim.Subject!.HasScope(Scopes.Email))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;

                    if (claim.Subject!.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;

                    yield break;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }
    }
}

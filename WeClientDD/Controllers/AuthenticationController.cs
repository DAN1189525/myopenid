using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;

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
                RedirectUri=Url.IsLocalUrl(returnUrl)?returnUrl:"/" 
            };
            return Challenge(properties,OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}

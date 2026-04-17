using Widiny.Stock.Web.Models.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace Widiny.Stock.Web.Controllers;

[AllowAnonymous]
public class AccountController : Controller
{
    private const string PendingAdminEmailSessionKey = "PendingAdminEmail";
    private readonly AdminAuthOptions _adminAuthOptions;

    public AccountController(IOptions<AdminAuthOptions> adminAuthOptions)
    {
        _adminAuthOptions = adminAuthOptions.Value;
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Dashboard", "Home");
        }

        return View(new AdminLoginViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Login(AdminLoginViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (!string.Equals(model.Email, _adminAuthOptions.Email, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(model.Password, _adminAuthOptions.Password, StringComparison.Ordinal))
        {
            ModelState.AddModelError(string.Empty, "로그인 정보가 올바르지 않습니다.");
            return View(model);
        }

        HttpContext.Session.SetString(PendingAdminEmailSessionKey, model.Email);

        return RedirectToAction(nameof(VerifyAuthenticator), new { model.ReturnUrl });
    }

    [HttpGet]
    public IActionResult VerifyAuthenticator(string? returnUrl = null)
    {
        if (string.IsNullOrWhiteSpace(HttpContext.Session.GetString(PendingAdminEmailSessionKey)))
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAuthenticator(VerifyAuthenticatorViewModel model)
    {
        var pendingEmail = HttpContext.Session.GetString(PendingAdminEmailSessionKey);

        if (string.IsNullOrWhiteSpace(pendingEmail))
        {
            return RedirectToAction(nameof(Login), new { model.ReturnUrl });
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var isTotpValid = VerifyTotp(model.Code);
        if (!isTotpValid)
        {
            ModelState.AddModelError(string.Empty, "Google Authenticator 코드가 유효하지 않습니다.");
            return View(model);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, pendingEmail),
            new(ClaimTypes.Email, pendingEmail),
            new(ClaimTypes.Role, "Admin")
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        HttpContext.Session.Remove(PendingAdminEmailSessionKey);

        if (!string.IsNullOrWhiteSpace(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
        {
            return LocalRedirect(model.ReturnUrl);
        }

        return RedirectToAction("Dashboard", "Home");
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    private bool VerifyTotp(string code)
    {
        if (string.IsNullOrWhiteSpace(_adminAuthOptions.TotpSecretBase32))
        {
            return false;
        }

        try
        {
            return TotpUtility.VerifyCode(_adminAuthOptions.TotpSecretBase32, code);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

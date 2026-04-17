using Widiny.Stock.Web.Models.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Widiny.Stock.Web.Controllers;

[AllowAnonymous]
public class AccountController : Controller
{
    private const string PendingAdminLoginIdSessionKey = "PendingAdminLoginId";
    private readonly AdminAccountStore _adminAccountStore;

    public AccountController(AdminAccountStore adminAccountStore)
    {
        _adminAccountStore = adminAccountStore;
    }

    [HttpGet]
    public IActionResult Register()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Dashboard", "Home");
        }

        return View(new AdminRegisterViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Register(AdminRegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var isRegistered = _adminAccountStore.TryRegister(model);
        if (!isRegistered)
        {
            ModelState.AddModelError(string.Empty, "이미 사용 중인 Login ID 입니다.");
            return View(model);
        }

        TempData["RegisterSuccess"] = "관리자 등록이 완료되었습니다. Google Authenticator를 설정한 뒤 로그인하세요.";
        return RedirectToAction(nameof(Login));
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

        if (!_adminAccountStore.VerifyCredentials(model.LoginId, model.Password))
        {
            ModelState.AddModelError(string.Empty, "로그인 정보가 올바르지 않습니다.");
            return View(model);
        }

        HttpContext.Session.SetString(PendingAdminLoginIdSessionKey, model.LoginId);

        return RedirectToAction(nameof(VerifyAuthenticator), new { model.ReturnUrl });
    }

    [HttpGet]
    public IActionResult VerifyAuthenticator(string? returnUrl = null)
    {
        if (string.IsNullOrWhiteSpace(HttpContext.Session.GetString(PendingAdminLoginIdSessionKey)))
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAuthenticator(VerifyAuthenticatorViewModel model)
    {
        var pendingLoginId = HttpContext.Session.GetString(PendingAdminLoginIdSessionKey);

        if (string.IsNullOrWhiteSpace(pendingLoginId))
        {
            return RedirectToAction(nameof(Login), new { model.ReturnUrl });
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var isTotpValid = VerifyTotp(pendingLoginId, model.Code);
        if (!isTotpValid)
        {
            ModelState.AddModelError(string.Empty, "Google Authenticator 코드가 유효하지 않습니다.");
            return View(model);
        }

        var displayName = _adminAccountStore.GetDisplayName(pendingLoginId);
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, pendingLoginId),
            new(ClaimTypes.Email, pendingLoginId),
            new(ClaimTypes.Name, displayName),
            new(ClaimTypes.Role, "Admin")
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        HttpContext.Session.Remove(PendingAdminLoginIdSessionKey);

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

    private bool VerifyTotp(string loginId, string code)
    {
        var secret = _adminAccountStore.GetTotpSecretByLoginId(loginId);
        if (string.IsNullOrWhiteSpace(secret))
        {
            return false;
        }

        try
        {
            return TotpUtility.VerifyCode(secret, code);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

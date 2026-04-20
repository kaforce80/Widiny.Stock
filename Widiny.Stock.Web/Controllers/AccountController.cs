using Widiny.Stock.Web.Models.Auth;
using Widiny.Stock.Web.Services.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Widiny.Stock.Web.Controllers;

[AllowAnonymous]
[AutoValidateAntiforgeryToken]
public class AccountController(AdminAccountService adminAccountService) : Controller
{
    private const string PendingAdminLoginIdSessionKey = "PendingAdminLoginId";

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
    public async Task<IActionResult> Register(AdminRegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var isRegistered = await adminAccountService.TryRegisterAsync(model);
        if (!isRegistered)
        {
            ModelState.AddModelError(string.Empty, "이미 사용 중인 Login ID 입니다.");
            return View(model);
        }

        await adminAccountService.AddAuditLogAsync(model.LoginId, "REGISTER", true, "Admin registered", GetRemoteIpAddress());
        return RedirectToAction(nameof(SetupAuthenticator), new { loginId = model.LoginId });
    }

    [HttpGet]
    public async Task<IActionResult> SetupAuthenticator(string loginId)
    {
        if (string.IsNullOrWhiteSpace(loginId))
        {
            return RedirectToAction(nameof(Login));
        }

        var secretKey = await adminAccountService.GetAuthenticatorSetupKeyAsync(loginId);
        if (string.IsNullOrWhiteSpace(secretKey))
        {
            return RedirectToAction(nameof(Login));
        }

        var issuer = Uri.EscapeDataString("Widiny Stock");
        var accountName = Uri.EscapeDataString(loginId);
        var otpAuthUri = $"otpauth://totp/{issuer}:{accountName}?secret={secretKey}&issuer={issuer}&digits=6";

        var qrCodeImageUrl = $"https://api.qrserver.com/v1/create-qr-code/?size=240x240&data={Uri.EscapeDataString(otpAuthUri)}";

        var viewModel = new AuthenticatorSetupViewModel
        {
            LoginId = loginId,
            SecretKey = secretKey,
            OtpAuthUri = otpAuthUri,
            QrCodeImageUrl = qrCodeImageUrl
        };

        return View(viewModel);
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Dashboard", "Home");
        }

        var safeReturnUrl = ValidateReturnUrl(returnUrl);
        return View(new AdminLoginViewModel { ReturnUrl = safeReturnUrl });
    }

    [HttpPost]
    public async Task<IActionResult> Login(AdminLoginViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var result = await adminAccountService.VerifyCredentialsAsync(model.LoginId, model.Password, GetRemoteIpAddress());
        if (result.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty, $"로그인이 잠겼습니다. 잠시 후 다시 시도하세요. ({result.LockoutEndUtc:HH:mm} UTC)");
            return View(model);
        }

        if (result.RequiresTwoFactorSetup)
        {
            return RedirectToAction(nameof(SetupAuthenticator), new { loginId = model.LoginId });
        }

        if (!result.IsSuccess)
        {
            ModelState.AddModelError(string.Empty, "로그인 정보가 올바르지 않습니다.");
            return View(model);
        }

        HttpContext.Session.SetString(PendingAdminLoginIdSessionKey, model.LoginId);
        var safeReturnUrl = ValidateReturnUrl(model.ReturnUrl);

        return RedirectToAction(nameof(VerifyAuthenticator), new { returnUrl = safeReturnUrl });
    }

    [HttpGet]
    public IActionResult VerifyAuthenticator(string? returnUrl = null)
    {
        if (string.IsNullOrWhiteSpace(HttpContext.Session.GetString(PendingAdminLoginIdSessionKey)))
        {
            return RedirectToAction(nameof(Login), new { returnUrl = ValidateReturnUrl(returnUrl) });
        }

        return View(new VerifyAuthenticatorViewModel { ReturnUrl = ValidateReturnUrl(returnUrl) });
    }

    [HttpPost]
    public async Task<IActionResult> VerifyAuthenticator(VerifyAuthenticatorViewModel model)
    {
        var pendingLoginId = HttpContext.Session.GetString(PendingAdminLoginIdSessionKey);

        if (string.IsNullOrWhiteSpace(pendingLoginId))
        {
            return RedirectToAction(nameof(Login), new { returnUrl = ValidateReturnUrl(model.ReturnUrl) });
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var verificationResult = await adminAccountService.VerifyTwoFactorOrRecoveryAsync(
            pendingLoginId,
            model.Code,
            GetRemoteIpAddress());

        if (verificationResult.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty, $"인증이 잠겼습니다. 잠시 후 다시 시도하세요. ({verificationResult.LockoutEndUtc:HH:mm} UTC)");
            return View(model);
        }

        if (!verificationResult.IsSuccess)
        {
            ModelState.AddModelError(string.Empty, "Google Authenticator 코드 또는 복구 코드가 유효하지 않습니다.");
            return View(model);
        }

        var displayName = await adminAccountService.GetDisplayNameAsync(pendingLoginId);
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
        await adminAccountService.AddAuditLogAsync(
            pendingLoginId,
            "LOGIN_SUCCESS",
            true,
            verificationResult.UsedRecoveryCode ? "Signed in with recovery code" : "Signed in with TOTP",
            GetRemoteIpAddress());

        HttpContext.Session.Remove(PendingAdminLoginIdSessionKey);

        var safeReturnUrl = ValidateReturnUrl(model.ReturnUrl);
        if (!string.IsNullOrWhiteSpace(safeReturnUrl))
        {
            return LocalRedirect(safeReturnUrl);
        }

        return RedirectToAction("Dashboard", "Home");
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> Security()
    {
        var loginId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        var model = new SecurityManagementViewModel
        {
            TwoFactorEnabled = await adminAccountService.IsTwoFactorEnabledAsync(loginId)
        };

        return View(model);
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> DisableTwoFactor(SecurityManagementViewModel model)
    {
        var loginId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        if (!await adminAccountService.ConfirmPasswordAsync(loginId, model.DisableTwoFactorPassword))
        {
            ModelState.AddModelError(string.Empty, "2차 인증 비활성화를 위해 현재 비밀번호 확인이 필요합니다.");
            model.TwoFactorEnabled = await adminAccountService.IsTwoFactorEnabledAsync(loginId);
            return View("Security", model);
        }

        await adminAccountService.DisableTwoFactorAsync(loginId);
        TempData["SecurityMessage"] = "2차 인증이 비활성화되었습니다.";
        return RedirectToAction(nameof(Security));
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ResetTwoFactor(SecurityManagementViewModel model)
    {
        var loginId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        if (!await adminAccountService.ConfirmPasswordAsync(loginId, model.ResetTwoFactorPassword))
        {
            ModelState.AddModelError(string.Empty, "2차 인증 재설정을 위해 현재 비밀번호 확인이 필요합니다.");
            model.TwoFactorEnabled = await adminAccountService.IsTwoFactorEnabledAsync(loginId);
            return View("Security", model);
        }

        await adminAccountService.ResetTwoFactorAsync(loginId);
        TempData["SecurityMessage"] = "2차 인증 시크릿이 재설정되었습니다. 다시 등록하세요.";
        return RedirectToAction(nameof(SetupAuthenticator), new { loginId });
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> RegenerateRecoveryCodes(SecurityManagementViewModel model)
    {
        var loginId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        if (!await adminAccountService.ConfirmPasswordAsync(loginId, model.ResetTwoFactorPassword))
        {
            ModelState.AddModelError(string.Empty, "복구 코드 재생성을 위해 현재 비밀번호 확인이 필요합니다.");
            model.TwoFactorEnabled = await adminAccountService.IsTwoFactorEnabledAsync(loginId);
            return View("Security", model);
        }

        var recoveryCodes = await adminAccountService.GenerateNewRecoveryCodesAsync(loginId);
        model.TwoFactorEnabled = await adminAccountService.IsTwoFactorEnabledAsync(loginId);
        model.RecoveryCodes = recoveryCodes;
        TempData["SecurityMessage"] = "새 복구 코드가 생성되었습니다. 안전한 장소에 보관하세요.";

        return View("Security", model);
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ChangePassword(SecurityManagementViewModel model)
    {
        var loginId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        if (!ModelState.IsValid)
        {
            model.TwoFactorEnabled = await adminAccountService.IsTwoFactorEnabledAsync(loginId);
            return View("Security", model);
        }

        var changed = await adminAccountService.ChangePasswordAsync(loginId, model.CurrentPassword, model.NewPassword);
        if (!changed)
        {
            ModelState.AddModelError(string.Empty, "현재 비밀번호가 올바르지 않습니다.");
            model.TwoFactorEnabled = await adminAccountService.IsTwoFactorEnabledAsync(loginId);
            return View("Security", model);
        }

        TempData["SecurityMessage"] = "비밀번호가 변경되었습니다.";
        return RedirectToAction(nameof(Security));
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await adminAccountService.AddAuditLogAsync(User.FindFirstValue(ClaimTypes.NameIdentifier), "LOGOUT", true, "User logged out", GetRemoteIpAddress());
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    private string? ValidateReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return null;
        }

        return Url.IsLocalUrl(returnUrl) ? returnUrl : null;
    }

    private string? GetRemoteIpAddress() => HttpContext.Connection.RemoteIpAddress?.ToString();
}

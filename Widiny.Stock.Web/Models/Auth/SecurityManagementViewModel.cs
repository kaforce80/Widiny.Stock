using System.ComponentModel.DataAnnotations;

namespace Widiny.Stock.Web.Models.Auth;

public class SecurityManagementViewModel
{
    public bool TwoFactorEnabled { get; set; }

    [DataType(DataType.Password)]
    public string DisableTwoFactorPassword { get; set; } = string.Empty;

    [DataType(DataType.Password)]
    public string ResetTwoFactorPassword { get; set; } = string.Empty;

    [DataType(DataType.Password)]
    public string CurrentPassword { get; set; } = string.Empty;

    [DataType(DataType.Password)]
    [RegularExpression(@"^(?=.*\d)(?=.*[^\w\s]).{8,}$", ErrorMessage = "새 비밀번호는 8자 이상이며 숫자와 특수문자를 포함해야 합니다.")]
    public string NewPassword { get; set; } = string.Empty;

    [DataType(DataType.Password)]
    [Compare(nameof(NewPassword), ErrorMessage = "새 비밀번호 확인이 일치하지 않습니다.")]
    public string ConfirmNewPassword { get; set; } = string.Empty;

    public List<string> RecoveryCodes { get; set; } = [];
}

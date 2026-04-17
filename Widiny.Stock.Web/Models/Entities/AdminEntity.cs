using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Widiny.Stock.Web.Models.Entities;

[Table("Account.Admin")]
public class AdminEntity : AuditableEntity
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(256)]
    public string LoginId { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string LastName { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string PrimaryEmail { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    [Required]
    public string PasswordSalt { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string TotpSecretBase32 { get; set; } = string.Empty;
}

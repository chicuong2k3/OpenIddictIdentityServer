using System.ComponentModel.DataAnnotations;

namespace OpenIddictIdentityServer.Models;

public class LoginModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$")]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}

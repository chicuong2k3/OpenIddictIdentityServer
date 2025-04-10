using Microsoft.AspNetCore.Identity;

namespace OpenIddictIdentityServer.Persistence;

public class ApplicationUser : IdentityUser
{
    public string? Picture { get; set; }
}

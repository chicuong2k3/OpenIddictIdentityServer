using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddictIdentityServer.Persistence;
using System.Security.Claims;

namespace OpenIddictIdentityServer.Pages;

public class ExternalLoginModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<ExternalLoginModel> _logger;

    public ExternalLoginModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<ExternalLoginModel> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    public IActionResult OnGet(string provider, string? returnUrl)
    {
        returnUrl ??= Url.Content("~/");
        var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback", values: new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return new ChallengeResult(provider, properties);
    }

    public async Task<IActionResult> OnGetCallbackAsync(string? returnUrl, string? remoteError = null)
    {
        returnUrl ??= Url.Content("~/");

        if (!string.IsNullOrEmpty(remoteError))
        {
            return Redirect("/login");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            _logger.LogError("External login info is null.");
            return Redirect("/login");
        }

        var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: true, bypassTwoFactor: true);

        if (signInResult.Succeeded)
        {
            _logger.LogInformation("User signed in with {Name} provider.", info.LoginProvider);
            return LocalRedirect(returnUrl);
        }

        //if (signInResult.IsLockedOut)
        //{
        //    return RedirectToPage("./Lockout");
        //}

        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        var name = info.Principal.FindFirstValue(ClaimTypes.Name);
        var picture = info.Principal.FindFirstValue("picture");

        if (string.IsNullOrEmpty(email))
        {
            _logger.LogError("Email not provided by Google");
            return Redirect("/login");
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                Picture = picture
            };

            var randomPassword = Guid.NewGuid().ToString();

            var createResult = await _userManager.CreateAsync(user, randomPassword);
            if (!createResult.Succeeded)
            {
                _logger.LogError("Failed to create user: {Errors}", string.Join(", ", createResult.Errors.Select(e => e.Description)));
                return Redirect("/login");
            }

            _logger.LogInformation("Created new user with email: {Email}", email);
        }

        var addLoginResult = await _userManager.AddLoginAsync(user, info);
        if (!addLoginResult.Succeeded)
        {
            _logger.LogError("Failed to add external login: {Errors}", string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
            return Redirect("/login");
        }

        _logger.LogInformation("Added external login for user: {Email}", email);

        await _signInManager.SignInAsync(user, isPersistent: true);

        return LocalRedirect(returnUrl);
    }
}

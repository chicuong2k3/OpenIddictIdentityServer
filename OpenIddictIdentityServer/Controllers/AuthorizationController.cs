using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using OpenIddictIdentityServer;
using System.Web;
using Microsoft.AspNetCore.Identity;
using System.Collections.Immutable;
using OpenIddictIdentityServer.Persistence;
using Microsoft.Extensions.Caching.Memory;

namespace OpenIddictBlazor.Controllers;

[ApiController]
public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthService _authService;
    private readonly IMemoryCache _cache;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<ApplicationUser> userManager,
        AuthService authService,
        IMemoryCache cache)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _userManager = userManager;
        _authService = authService;
        _cache = cache;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        // get the OpenID Connect request, including the client_id, response_type, scope, ...
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        var redirectUrl = _authService.BuildRedirectUrl(HttpContext);
        var isAuthenticated = _authService.IsAuthenticated(result, request);

        // if the user is not authenticated, we need to challenge the user (redirect to the login page)
        if (!isAuthenticated)
        {
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = redirectUrl
                });
        }

        // find the client application information in the database
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId ?? string.Empty) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        var userId = result.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;

        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Cannot find user from the token."
                }));
        }


        // get all requested scopes
        var requestedScopes = request.GetScopes();

        var authorizations = await _authorizationManager.FindAsync(
            subject: userId,
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: requestedScopes
        ).ToListAsync();

        // get all consented scopes
        var consentedScopes = new HashSet<string>();
        foreach (var auth in authorizations)
        {
            var scopes = await _authorizationManager.GetScopesAsync(auth);
            consentedScopes.UnionWith(scopes);
        }

        // get the scopes that are not consented yet
        var newScopes = requestedScopes.Select(s => s.ToLower())
                                    .Except(consentedScopes.Select(s => s.ToLower()))
                                    .ToList();

        // if the user has not consented to all requested scopes,
        // we need to redirect to the consent page
        var state = request.State ?? Guid.NewGuid().ToString("N");
        var cacheKey = $"consent_{state}";

        if (newScopes.Any())
        {
            var consentResult = HttpContext.Request.Query["consent_result"].ToString();
            if (!string.IsNullOrEmpty(consentResult))
            {
                var cachedData = _cache.Get<string>(cacheKey);
                if (cachedData != null && consentResult == "accepted" && cachedData == string.Join(" ", newScopes))
                {
                    _cache.Remove(cacheKey);
                }
                else
                {
                    return BadRequest("Invalid consent response.");
                }
            }
            else
            {
                _cache.Set(cacheKey, string.Join(" ", newScopes), TimeSpan.FromMinutes(5));
                var parameters = _authService.ParseParameters(HttpContext, new List<string> { "scope" });
                parameters["scope"] = string.Join(" ", requestedScopes);
                parameters["state"] = state;
                var consentUrl = $"/consent{QueryString.Create(parameters)}";
                return Redirect(consentUrl);
            }
        }

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, user.Email)
            .SetClaim(Claims.Name, result.Principal?.FindFirst(ClaimTypes.Name)?.Value ?? userId)
            .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray())
            .SetScopes(request.GetScopes())
            .SetResources(await _scopeManager.ListResourcesAsync(request.GetScopes()).ToListAsync());

        // check if there is an existing authorization that has all requested scopes
        object? authorization = null;
        foreach (var auth in authorizations)
        {
            var authScopes = await _authorizationManager.GetScopesAsync(auth);
            if (requestedScopes.All(rs => authScopes.Contains(rs)))
            {
                authorization = auth;
                break;
            }
        }

        // if there is no existing authorization, create a new one
        if (authorization == null)
        {
            authorization = await _authorizationManager.CreateAsync(
                identity: identity,
                subject: userId,
                client: await _applicationManager.GetClientIdAsync(application) ?? string.Empty,
                type: AuthorizationTypes.Permanent,
                scopes: requestedScopes.ToImmutableArray()
            );
        }


        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(AuthService.GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");

        var result =
            await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var userId = result.Principal?.GetClaim(Claims.Subject);

        var user = await _userManager.FindByIdAsync(userId ?? string.Empty);

        if (user == null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Cannot find user from the token."
                }));
        }

        var identity = new ClaimsIdentity(result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, user.Email)
            .SetClaim(Claims.Name, result.Principal?.FindFirst(ClaimTypes.Name)?.Value ?? userId)
            .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray())
            .SetScopes(request.GetScopes())
            .SetResources(await _scopeManager.ListResourcesAsync(request.GetScopes()).ToListAsync());

        identity.SetDestinations(AuthService.GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

}
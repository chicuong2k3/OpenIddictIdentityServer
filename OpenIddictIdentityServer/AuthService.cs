using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;

namespace OpenIddictIdentityServer;

public class AuthService
{
    public string BuildRedirectUrl(HttpContext httpContext)
    {
        var parameters = ParseParameters(httpContext);
        return httpContext.Request.PathBase + httpContext.Request.Path + QueryString.Create(parameters);
    }

    public IDictionary<string, StringValues> ParseParameters(HttpContext httpContext, List<string>? excluding = null)
    {
        var parameters = httpContext.Request.HasFormContentType ?
                httpContext.Request.Form.Where(parameter => excluding == null || !excluding.Contains(parameter.Key)).ToDictionary(q => q.Key, q => q.Value) :
                httpContext.Request.Query.Where(parameter => excluding == null || !excluding.Contains(parameter.Key)).ToDictionary(q => q.Key, q => q.Value);

        return parameters;
    }

    public bool IsAuthenticated(AuthenticateResult result, OpenIddictRequest request)
    {
        if (result == null || !result.Succeeded)
        {
            return false;
        }

        if (request.MaxAge != null && result.Properties?.IssuedUtc != null)
        {
            var maxAge = TimeSpan.FromSeconds(request.MaxAge.Value);
            var expired = DateTimeOffset.UtcNow - result.Properties.IssuedUtc > maxAge;
            if (expired)
            {
                return false;
            }
        }

        return true;
    }

    public static IEnumerable<string> GetDestinations(Claim claim)

    {
        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;

                if (claim.Subject != null && claim.Subject.HasScope(Scopes.Profile))
                {
                    yield return Destinations.IdentityToken;
                }

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject != null && claim.Subject.HasScope(Scopes.Email))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;
            case Claims.Role:
                yield return Destinations.AccessToken;
                if (claim.Subject != null && claim.Subject.HasScope(Scopes.Roles))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
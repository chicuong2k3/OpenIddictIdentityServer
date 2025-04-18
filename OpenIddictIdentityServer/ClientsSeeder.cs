﻿using OpenIddict.Abstractions;
using OpenIddictIdentityServer.Persistence;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictIdentityServer;

public class ClientsSeeder
{
    private readonly IServiceProvider _serviceProvider;

    public ClientsSeeder(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task AddScopesAsync()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "email", DisplayName = "Email address" });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "profile", DisplayName = "User profile" });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "roles", DisplayName = "User roles" });

        var existingScope = await scopeManager.FindByNameAsync("api");
        if (existingScope == null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "api",
                DisplayName = "Access to the API",
                Resources =
                {
                    "resource_server"
                }
            });
        }

    }

    public async Task AddClientsAsync()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await dbContext.Database.EnsureCreatedAsync();

        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var client = await applicationManager.FindByClientIdAsync("web_client");

        if (client == null)
        {
            await applicationManager.CreateAsync(new()
            {
                ClientId = SampleClient.ClientId,
                ClientSecret = SampleClient.ClientSecret,
                DisplayName = SampleClient.ClientDisplayName,
                ConsentType = ConsentTypes.Explicit,
                RedirectUris =
                {
                    new Uri("https://localhost:9090/signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:9090/signout-callback-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    $"{Permissions.Prefixes.Scope}api"
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }


    }
}

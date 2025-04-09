using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddictIdentityServer;
using OpenIddictIdentityServer.Components;
using OpenIddictIdentityServer.Persistence;
using Sysinfocus.AspNetCore.Components;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSysinfocus(false);

builder.Services.AddMemoryCache();
builder.Services.AddControllers();


builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need to replace the default OpenIddict entities.
    options.UseOpenIddict();
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        // Note: call ReplaceDefaultEntities() to replace the default entities.
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
     .AddServer(options =>
     {
         // Enable the token endpoint.
         options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token");

         // Enable the client credentials flow.
         options.AllowAuthorizationCodeFlow();

         // Register the signing and encryption credentials.
         options.AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();

         // Register the ASP.NET Core host and configure the ASP.NET Core options.
         options.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
                .EnableTokenEndpointPassthrough();
     })
     .AddValidation(options =>
     {
         options.UseLocalServer();
         options.UseAspNetCore();
     })
     .AddClient(options =>
     {
         options
            .AllowAuthorizationCodeFlow();
     });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        // Configure the cookie authentication options.
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/access-denied";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.MaxAge = TimeSpan.FromDays(1);
        options.SlidingExpiration = true;
    });


builder.Services.AddHttpContextAccessor();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddScoped<AuthService>();

builder.Services.AddSingleton<ClientsSeeder>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();
    seeder.AddScopesAsync().GetAwaiter();
    await seeder.AddClientsAsync();
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();


app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();


app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapControllers();

app.Run();

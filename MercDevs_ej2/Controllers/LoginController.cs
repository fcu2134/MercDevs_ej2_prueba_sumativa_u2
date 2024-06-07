using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MercDevs_ej2.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using System;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

public class LoginController : Controller
{
    private readonly MercydevsEjercicio2Context _context;
    private readonly IConfiguration _configuration;
    public LoginController(MercydevsEjercicio2Context context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    public IActionResult Index()
    {
        return View(new MercDevs_ej2.Models.Login());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(Login login, string action)
    {
        if (action == "login")
        {
            return await LoginUser(login);
        }
        else if (action == "register")
        {
            return await RegisterUser(login);
        }

        return View(login);
    }

    private async Task<IActionResult> LoginUser(Login login)
    {
        if (ModelState.IsValid)
        {
            Usuario? usuarioExistente = await _context.Usuarios.FirstOrDefaultAsync(u => u.Correo == login.Correo);

            if (usuarioExistente != null)
            {
                string decryptedPassword = DecryptString(usuarioExistente.Password);


                if (login.Password == decryptedPassword)
                {
                    var claims = new List<Claim>()
                    {
                      
                        new Claim(ClaimTypes.Email, usuarioExistente.Correo)
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties();

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties
                    );

                    return RedirectToAction("Index", "Home");
                }
            }
        }

        ViewData["mensaje"] = "Correo o contraseña incorrectos.";
        return View("Index", login);
    }

    private async Task<IActionResult> RegisterUser(Login login)
    {
        if (ModelState.IsValid)
        {
            try
            {
                Usuario? usuarioExistente = await _context.Usuarios.FirstOrDefaultAsync(u => u.Correo == login.Correo);

                if (usuarioExistente == null)
                {
                    string encryptedPassword = EncryptString(login.Password ?? string.Empty);

                    string? nombre = string.IsNullOrEmpty(login.Nombre) ? "Nombre" : login.Nombre;
                    string? apellido = string.IsNullOrEmpty(login.Apellido) ? "Apellido" : login.Apellido;
                    Usuario usuario = new Usuario()
                    {
                        Nombre = nombre,
                        Apellido = apellido,
                        Correo = login.Correo ?? string.Empty,
                        Password = encryptedPassword
                    };

                    _context.Usuarios.Add(usuario);
                    await _context.SaveChangesAsync();

                    ViewData["mensaje"] = "Usuario registrado correctamente.";
                }
                else
                {
                    ViewData["mensaje"] = "El correo ya está registrado.";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al crear usuario: {ex.Message}");
                ViewData["mensaje"] = "Ocurrió un error al crear el usuario.";
            }
        }
        else
        {
            ViewData["mensaje"] = "Datos de formulario inválidos.";
        }

        return View("Index", login);
    }

    // Método para encriptar texto usando TripleDES
    public string EncryptString(string texto)
    {
        string? key = _configuration["EncryptionKey"];

        if (key == null)
        {
            // Manejar el caso donde la clave de encriptación es nula
            throw new InvalidOperationException("La clave de encriptación no está configurada.");
        }

        byte[] iv = new byte[8]; // Inicializa el vector de inicialización (IV) con ceros
        using (var des = TripleDES.Create())
        {
            des.Key = Encoding.UTF8.GetBytes(key.PadRight(24)); // Asegúrate de que la clave tenga 24 bytes
            des.IV = iv;
            var encryptor = des.CreateEncryptor();
            byte[] bytes = Encoding.UTF8.GetBytes(texto);
            return Convert.ToBase64String(encryptor.TransformFinalBlock(bytes, 0, bytes.Length));
        }
    }

    // Método para desencriptar texto usando TripleDES
    public string DecryptString(string encryptedText)
    {
        string? key = _configuration["EncryptionKey"];

        if (key != null)
        {
            byte[] iv = new byte[8]; // Inicializa el vector de inicialización (IV) con ceros
            using (var des = TripleDES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes(key.PadRight(24)); // Asegúrate de que la clave tenga 24 bytes
                des.IV = iv;
                var decryptor = des.CreateDecryptor();
                byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
        // Si key es nulo, devuelve una cadena vacía
        return string.Empty;
    }

}
    


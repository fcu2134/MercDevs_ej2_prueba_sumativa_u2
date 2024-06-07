namespace MercDevs_ej2.Models
{
    using System.ComponentModel.DataAnnotations;

    public class Login
    {
        public string? Nombre { get; set; }

        public string? Apellido { get; set; }
        [DataType(DataType.EmailAddress)]
        [Required(ErrorMessage = "El correo es obligatorio.")]
        public string? Correo { get; set; } 

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "La contraseña es obligatoria.")]
        public string? Password { get; set; } 
    }
}

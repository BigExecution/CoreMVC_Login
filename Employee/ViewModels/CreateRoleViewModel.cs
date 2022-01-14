using System.ComponentModel.DataAnnotations;

namespace Employee.ViewModels
{
    public class CreateRoleViewModel
    {
        [Required]
        public string RoleName { get; set; }
    }
}

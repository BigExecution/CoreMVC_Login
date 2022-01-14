using Microsoft.AspNetCore.Identity;

namespace Employee.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string City { get; set; }
    }
}

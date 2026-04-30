using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GestaoEventos.Controllers
{
    [Authorize(Roles = "Dono,Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public AdminController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            var users = await _userManager.Users.ToListAsync();

            var usersWithRoles = new List<(IdentityUser User, IList<string> Roles)>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                usersWithRoles.Add((user, roles));
            }

            return View(usersWithRoles);
        }

        [HttpPost]
        public async Task<IActionResult> PromoverAdmin(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            if (!await _userManager.IsInRoleAsync(user, "Admin"))
            {
                await _userManager.RemoveFromRoleAsync(user, "User");
                await _userManager.AddToRoleAsync(user, "Admin");
            }

            TempData["Mensagem"] = $"Usuário {user.Email} foi promovido a Admin!";
            TempData["TipoMensagem"] = "success";

            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> RebaixarUser(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            var usuarioLogado = await _userManager.GetUserAsync(User);

            var logadoEhDono = await _userManager.IsInRoleAsync(usuarioLogado, "Dono");


            var alvoEhDono = await _userManager.IsInRoleAsync(user, "Dono");

            if (usuarioLogado?.Id == userId)
            {
                TempData["Mensagem"] = "Você não pode rebaixar a si mesmo!";
                TempData["TipoMensagem"] = "danger";
                return RedirectToAction("Index");
            }

            if (!logadoEhDono && alvoEhDono)
            {
                TempData["Mensagem"] = "Admin não pode alterar um Dono!";
                TempData["TipoMensagem"] = "danger";
                return RedirectToAction("Index");
            }

            await _userManager.RemoveFromRoleAsync(user, "Admin");
            await _userManager.AddToRoleAsync(user, "User");

            TempData["Mensagem"] = $"Usuário {user.Email} foi rebaixado para User!";
            TempData["TipoMensagem"] = "warning";

            return RedirectToAction("Index");
        }
    }
}
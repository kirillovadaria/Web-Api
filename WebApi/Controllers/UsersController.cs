using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using WebApi.Dto;
using WebApi.Models;
using WebApi.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api")]
    public class UsersController : Controller
    {
        private IUserService _userService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public UsersController(IUserService userService, IMapper mapper, IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _mapper = mapper;
            _appSettings = appSettings.Value;

        }

        // запрос на создание пользователя
        // POST api/createUser 
        [AllowAnonymous]
        [HttpPost("createUser")]
        public IActionResult Register([FromBody]UserDto userDto)
        {
            var user = _mapper.Map<User>(userDto);
            try
            {
                _userService.Create(user, userDto.Password);
                return Ok(new { message = "Пользователь успешно добавлен." });
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // запрос на получение токена
        // POST api/request 
        [AllowAnonymous]
        [HttpPost("request")]
        public IActionResult Authorization([FromBody]UserDto userDto)
        {
            try
            {
                var user = _userService.Authorization(userDto.Username, userDto.Password);
                
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Key);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    // Создаем утверждения для токена
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim(ClaimTypes.Name, user.Id.ToString())
                    }),
                    // Генерируем JWT
                    Expires = DateTime.UtcNow.AddDays(3),
                    // способ создания цифровой подписи
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token); // создается Json-представление токена

                // возвращаем клиенту token
                return Ok(new { Token = tokenString });
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }


        }

        // запрос на получение списка пользователей
        // GET api/usersList 
        [HttpGet("usersList")]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            var userDtos = _mapper.Map<IList<UserDto>>(users);
            return Ok(userDtos);   
        }
    }
}

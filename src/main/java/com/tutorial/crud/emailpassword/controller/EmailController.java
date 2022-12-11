package com.tutorial.crud.emailpassword.controller;

import com.tutorial.crud.dto.Mensaje;
import com.tutorial.crud.emailpassword.dto.ChangePasswordDTO;
import com.tutorial.crud.emailpassword.dto.EmailValuesDTO;
import com.tutorial.crud.emailpassword.service.EmailService;
import com.tutorial.crud.security.entity.Usuario;
import com.tutorial.crud.security.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/email-password")
@CrossOrigin
public class EmailController {

    @Autowired
    EmailService emailService;

    @Autowired
    UsuarioService usuarioService;

    @Value("${spring.mail.username}")
    private String mailFrom;

    private static final String subject = "Cambio de contraseña";

    @Autowired
    PasswordEncoder passwordEncoder;

    @PostMapping("/send-email")
    public ResponseEntity<?> sendEmail(@RequestBody EmailValuesDTO dto){
        Optional<Usuario> usuarioOptional = usuarioService.getByNombreUsuarioOrEmail(dto.getMailTo());
        if(!usuarioOptional.isPresent()){
            return new ResponseEntity(new Mensaje("No existe ningún usuario con ese email"), HttpStatus.NOT_FOUND);
        }
        Usuario usuario = usuarioOptional.get();

        dto.setMailFrom(mailFrom);
        dto.setMailTo(usuario.getEmail());
        dto.setSubject(subject);
        dto.setUserName(usuario.getNombreUsuario());
        UUID uuid = UUID.randomUUID();
        String tokenPassword = uuid.toString();
        dto.setTokenPassword(tokenPassword);

        usuario.setTokenPassword(tokenPassword);
        usuarioService.save(usuario);

        emailService.sendEmail(dto);
        return new ResponseEntity(new Mensaje("Te hemos enviado un correo"), HttpStatus.OK);
    }
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordDTO dto, BindingResult bindingResult){
        if (bindingResult.hasErrors()){
            return new ResponseEntity(new Mensaje("Campos errorenos"), HttpStatus.BAD_REQUEST);
        }
        if (!dto.getPassword().equals(dto.getConfirmPassword())){
            return new ResponseEntity(new Mensaje("Las constraseñas no coinciden"), HttpStatus.BAD_REQUEST);
        }

        Optional<Usuario> usuarioOptional = usuarioService.getByTokenPassword(dto.getTokenPassword());
        if(!usuarioOptional.isPresent()){
            return new ResponseEntity(new Mensaje("No existe ningún usuario con ese email"), HttpStatus.NOT_FOUND);
        }
        Usuario usuario = usuarioOptional.get();
        String newPassword = passwordEncoder.encode(dto.getPassword());
        usuario.setPassword(newPassword);
        usuario.setTokenPassword(null);
        usuarioService.save(usuario);
        return new ResponseEntity(new Mensaje("Contraseña actualizada"), HttpStatus.OK);
    }
}


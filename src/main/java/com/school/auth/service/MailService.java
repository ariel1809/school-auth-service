package com.school.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${app.mail.from:no-reply@school.local}")
    private String from;

    public void sendPasswordResetEmail(String to, String name, String resetLink) {
        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setFrom(from);
            msg.setTo(to);
            msg.setSubject("Réinitialisation de votre mot de passe");
            msg.setText("""
                    Bonjour %s,

                    Vous avez demandé la réinitialisation de votre mot de passe.

                    Cliquez sur ce lien pour définir un nouveau mot de passe (valide 30 minutes) :
                    %s

                    Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.

                    L'équipe School Management
                    """.formatted(name != null ? name : "", resetLink));
            mailSender.send(msg);
        } catch (Exception ex) {
            log.warn("Could not send password reset email to {}: {}", to, ex.getMessage());
        }
    }
}
package com.example.demo.email;

/**
 * Hand-rolled inline HTML so we don't drag in a templating engine for two
 * emails. Each method returns a complete, self-contained HTML body — Resend
 * doesn't need a <!DOCTYPE> wrapper but most mail clients render better with
 * one. The plain-text fallback link is always shown beneath the button in
 * case the user's client strips the styled CTA.
 */
public final class EmailTemplates {

    private EmailTemplates() {}

    public static String verification(String name, String verifyUrl) {
        String safeName = escape(name == null || name.isBlank() ? "회원" : name);
        return wrap("이메일 인증",
                "<h1 style=\"font-size:20px;margin:0 0 12px;\">안녕하세요, " + safeName + "님</h1>"
                        + "<p style=\"margin:0 0 16px;color:#374151;\">"
                        + "용산구 홈페이지 회원가입을 진행해주셔서 감사합니다. 아래 버튼을 눌러 이메일 인증을 완료해주세요. "
                        + "인증이 완료되어야 회원 기능을 이용하실 수 있습니다."
                        + "</p>"
                        + "<p style=\"margin:24px 0;\">"
                        + "<a href=\"" + verifyUrl + "\" "
                        + "style=\"display:inline-block;padding:12px 24px;background:#2f5597;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;\">"
                        + "이메일 인증하기</a>"
                        + "</p>"
                        + "<p style=\"margin:16px 0;font-size:13px;color:#6b7280;\">"
                        + "버튼이 동작하지 않으면 아래 주소를 복사해 브라우저 주소창에 붙여넣어주세요:<br>"
                        + "<span style=\"word-break:break-all;color:#2f5597;\">" + verifyUrl + "</span>"
                        + "</p>"
                        + "<p style=\"margin:16px 0;font-size:13px;color:#6b7280;\">"
                        + "이 링크는 24시간 동안 유효합니다. 본인이 가입하지 않으셨다면 이 메일을 무시하셔도 됩니다."
                        + "</p>"
        );
    }

    public static String passwordReset(String name, String resetUrl) {
        String safeName = escape(name == null || name.isBlank() ? "회원" : name);
        return wrap("비밀번호 재설정",
                "<h1 style=\"font-size:20px;margin:0 0 12px;\">비밀번호 재설정 요청</h1>"
                        + "<p style=\"margin:0 0 16px;color:#374151;\">"
                        + safeName + "님, 비밀번호 재설정을 요청하셨습니다. 아래 버튼을 눌러 새 비밀번호를 설정해주세요."
                        + "</p>"
                        + "<p style=\"margin:24px 0;\">"
                        + "<a href=\"" + resetUrl + "\" "
                        + "style=\"display:inline-block;padding:12px 24px;background:#dc2626;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;\">"
                        + "비밀번호 재설정</a>"
                        + "</p>"
                        + "<p style=\"margin:16px 0;font-size:13px;color:#6b7280;\">"
                        + "버튼이 동작하지 않으면 아래 주소를 복사해 브라우저 주소창에 붙여넣어주세요:<br>"
                        + "<span style=\"word-break:break-all;color:#2f5597;\">" + resetUrl + "</span>"
                        + "</p>"
                        + "<p style=\"margin:16px 0;font-size:13px;color:#6b7280;\">"
                        + "이 링크는 1시간 동안 유효합니다. 본인이 요청하지 않으셨다면 이 메일을 무시하셔도 됩니다 — 비밀번호는 변경되지 않습니다."
                        + "</p>"
        );
    }

    private static String wrap(String title, String body) {
        return "<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>" + escape(title) + "</title></head>"
                + "<body style=\"margin:0;padding:0;background:#f5f7fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Apple SD Gothic Neo','Noto Sans KR',sans-serif;\">"
                + "<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" width=\"100%\" style=\"background:#f5f7fa;padding:32px 16px;\"><tr><td align=\"center\">"
                + "<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" width=\"560\" style=\"max-width:560px;background:#fff;border-radius:12px;padding:32px;text-align:left;\">"
                + body
                + "<hr style=\"border:none;border-top:1px solid #e5e7eb;margin:24px 0;\">"
                + "<p style=\"margin:0;font-size:12px;color:#9ca3af;text-align:center;\">용산구 홈페이지 · minhojan-world.site</p>"
                + "</table></td></tr></table></body></html>";
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}

const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

$(document).ready(function() {
    async function checkPasswordStrength(password) {
        const bar = document.getElementById('password-strength-bar');
        const strengthText = document.getElementById('strength-text');

        try {
            const response = await fetch('/password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ password })
            });

            if (response.ok) {
                const data = await response.json();
                const { strength } = data;

                if (strength === "weak") {
                    bar.style.width = "33%";
                    bar.className = "strength-weak";
                    strengthText.textContent = `Siła hasła: Słabe`;
                } else if (strength === "medium") {
                    bar.style.width = "66%";
                    bar.className = "strength-medium";
                    strengthText.textContent = `Siła hasła: Średnie`;
                } else {
                    bar.style.width = "100%";
                    bar.className = "strength-strong";
                    strengthText.textContent = `Siła hasła: Mocne`;
                }
            } else {
                console.error("Błąd podczas weryfikacji siły hasła");
            }
        } catch (error) {
            console.error("Błąd połączenia z serwerem:", error);
        }
    }

    function evaluatePasswordStrength() {
        const password = document.getElementById('password').value;
        checkPasswordStrength(password);
    }

    document.getElementById('password').addEventListener('input', evaluatePasswordStrength);

    $('#registrationForm input').on('input', function() {
        if ($('#name').val() && $('#login').val() && $('#password').val() && $('#email').val()) {
            $('#sendCodeButton').show();
        } else {
            $('#sendCodeButton').hide();
        }
    });

    $('#sendCodeButton').click(function(event) {
        event.preventDefault();

        var email = $('#email').val();

        $.ajax({
            type: 'POST',
            url: "https://localhost/send_registration_code",
            data: {
                email: email
            },
            headers: {
                'X-CSRFToken': csrfToken 
            },
            success: function(response) {
                alert(response.message);
                $('#registrationCodeLabel').show();
                $('#registration_code').show();
            },
            error: function(xhr, status, error) {
                const defaultMessage = "Wystąpił błąd podczas wysyłania kodu. Spróbuj ponownie.";
                const errorMessages = {
                    400: "Użytkownik o tym adresie e-mail już istnieje.",
                    429: "Za dużo zapytań. Spróbuj ponownie za chwilę."
                };

                const errorMessage = xhr.responseJSON?.message || errorMessages[xhr.status] || defaultMessage;
                alert(errorMessage);
            }
        });
    });
});

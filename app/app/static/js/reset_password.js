$(document).ready(function() {
    let userEmail = "";
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    $("#send-code-form").on("submit", function (e) {
        e.preventDefault();
        userEmail = $("#email").val();
        console.log("Email:", userEmail);
        $.ajax({
            url: "https://localhost/send_reset_code",
            type: "POST",
            data: {
                email: userEmail
            },
            headers: {
                'X-CSRFToken': csrfToken 
            },
            success: function (response) {
                console.log("Sukces:", response);
                $("#messages").html(`<p style="color: green;">${response.message}</p>`);
                $("#reset-password-form").show();
                $("#reset_email").val(userEmail);
                alert(response.message);
            },
            error: function (xhr) {
                console.log("Błąd:", xhr);
                const errorMessage = xhr.responseJSON.message || "Błąd podczas wysyłania kodu.";
                $("#messages").html(`<p style="color: red;">${errorMessage}</p>`);
                alert(errorMessage);
            }
        });
    });
});
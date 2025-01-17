$(document).ready(function() {
    const noteId = $('#is_public').data('note-id');
    const csrfToken = $('input[name="csrf_token"]').val();

    $('#is_public').on('change', function() {
        const isChecked = $(this).is(':checked');

        if (isChecked) {
            const confirmPublish = confirm("Czy na pewno chcesz wystawić tę notatkę jako publiczną?");
            if (!confirmPublish) {
                $(this).prop('checked', false);
                return;
            }
        }

        $.ajax({
            url: `/update_visibility/${noteId}`,
            type: 'POST',
            contentType: 'application/json',
            headers: {
                'X-CSRFToken': csrfToken 
            },
            data: JSON.stringify({ is_public: isChecked }),
            error: function(xhr) {
                alert("Wystąpił błąd podczas zmiany widoczności notatki.");
            }
        });
    });

    $('#add-user-form').on('submit', function(event) {
        event.preventDefault();

        const username = $('#new-username').val();
        if (!username) {
            alert("Wprowadź nazwę użytkownika.");
            return;
        }

        $.ajax({
            url: `https://localhost/add_shared_user/${noteId}`,
            type: 'POST',
            contentType: 'application/json', 
            headers: {
                'X-CSRFToken': csrfToken 
            },
            data: JSON.stringify({ username: username }),
            success: function(response) {
                if ($('#no-users').length) {
                    $('#no-users').remove(); 
                }
                $('#shared-users-list').append(`
                    <li id="user-${response.user_id}">
                        ${response.username}
                        <button class="remove-user" data-user-id="${response.user_id}">Usuń</button>
                    </li>
                `);
                $('#new-username').val('');
            },
            error: function(xhr) {
                let errorMessage;

                switch(xhr.status) {
                    case 400:
                        if (xhr.responseJSON.error === 'No username provided') {
                            errorMessage = "Proszę podać nazwę użytkownika.";
                        } else if (xhr.responseJSON.error === 'Cannot share with yourself') {
                            errorMessage = "Nie możesz udostępnić notatki samemu sobie.";
                        } else {
                            errorMessage = "Wystąpił błąd. Spróbuj ponownie.";
                        }
                        break;
                    case 403:
                        errorMessage = "Nie masz uprawnień do wykonania tej akcji.";
                        break;
                    case 404:
                        errorMessage = "Użytkownik o podanej nazwie nie istnieje.";
                        break;
                    default:
                        errorMessage = "Wystąpił nieznany błąd.";
                }
            }
        });
    });

    $(document).on('click', '.remove-user', function() {
        const userId = $(this).data('user-id');
        console.log('User ID:', userId);

        if (!confirm("Czy na pewno chcesz usunąć tego użytkownika?")) {
            return;
        }

        $.ajax({
            url: `https://localhost/remove_shared_user/${noteId}`,
            type: 'POST',
            contentType: 'application/json',
            headers: {
                'X-CSRFToken': csrfToken 
            },
            data: JSON.stringify({ user_id: parseInt(userId) }),    
            success: function(response) {
                $(`#user-${userId}`).remove();

                if (!$('#shared-users-list li').length) {
                    $('#shared-users-list').append('<li id="no-users">Brak użytkowników.</li>');
                }
            },
            error: function(xhr) {
                console.log(xhr.responseText);
                alert("Wystąpił błąd podczas usuwania użytkownika.");
            }
        });
    });
});
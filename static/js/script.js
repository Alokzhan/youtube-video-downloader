$(document).ready(function() {
    // Handle download form submission
    $('#downloadForm').submit(function(e) {
        e.preventDefault();
        const url = $('#videoUrl').val().trim();
        const format = $('#formatSelect').val();

        if (!url) {
            $('#status').html('<div class="alert alert-danger">Please enter a valid URL</div>');
            return;
        }

        $('#status').html('<div class="alert alert-info">Processing... <div class="spinner-border spinner-border-sm" role="status"></div></div>');
        $('#downloadBtn').prop('disabled', true);

        $.ajax({
            url: '/download',
            type: 'POST',
            data: {
                url: url,
                format: format
            },
            success: function(response) {
                if (response.error) {
                    showError(response.error);
                } else {
                    $('#status').html(`
                        <div class="alert alert-success">
                            <strong>${response.title}</strong> downloaded successfully!
                            <div class="mt-2">
                                <a href="/download_file/${response.filename}" class="btn btn-success download-btn">
                                    <i class="fas fa-download"></i> Download ${format.toUpperCase()}
                                </a>
                            </div>
                        </div>
                    `);
                }
            },
            error: function(xhr) {
                let errorMsg = 'An error occurred. Please try again.';
                if (xhr.responseJSON && xhr.responseJSON.error) {
                    errorMsg = xhr.responseJSON.error;
                }
                showError(errorMsg);
            },
            complete: function() {
                $('#downloadBtn').prop('disabled', false);
            }
        });
    });

    function showError(message) {
        $('#status').html(`<div class="alert alert-danger">${message}</div>`);
    }

    // Clear status message when user starts typing
    $('#videoUrl').on('input', function() {
        $('#status').empty();
    });
});
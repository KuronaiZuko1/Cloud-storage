function improvedDownload(url, filename) {
    fetch(url)
        .then(response => {
            // Check if the response is ok
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            // Get the content type
            const contentType = response.headers.get('Content-Type');
            // Handle blob response
            return response.blob().then(blob => {
                // Create a link element
                const link = document.createElement('a');
                // Create a URL for the blob
                const url = window.URL.createObjectURL(blob);
                // Set the filename based on the content-disposition header or fallback to filename provided
                const disposition = response.headers.get('Content-Disposition');
                const fileName = disposition ? disposition.split('filename=')[1] : filename;
                // Set link properties
                link.href = url;
                link.download = fileName || 'download';
                // Append to the body
                document.body.appendChild(link);
                // Trigger download
                link.click();
                // Clean up
                link.remove();
                window.URL.revokeObjectURL(url);
            });
        })
        .catch(error => {
            console.error('Download failed:', error);
        });
}
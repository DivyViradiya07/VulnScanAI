document.addEventListener('DOMContentLoaded', () => {
    const uploadBtn = document.getElementById('uploadBtn');
    const pdfFile = document.getElementById('pdfFile');
    const uploadStatus = document.getElementById('uploadStatus');
    const summaryDisplay = document.getElementById('summaryDisplay');
    const summaryPre = summaryDisplay.querySelector('pre');
    const chatInput = document.getElementById('chatInput');
    const sendBtn = document.getElementById('sendBtn');
    const chatMessages = document.getElementById('chatMessages');
    const uploadSpinner = document.getElementById('uploadSpinner');
    const chatSpinner = document.getElementById('chatSpinner');
    const clearChatBtn = document.getElementById('clearChatBtn');

    // Function to enable/disable UI elements
    const setUIState = (uploading, chatting) => {
        pdfFile.disabled = uploading || chatting;
        uploadBtn.disabled = uploading || chatting;
        chatInput.disabled = !summaryDisplay.classList.contains('flex') && !chatting; // Disable chat if no summary yet and not chatting
        sendBtn.disabled = !summaryDisplay.classList.contains('flex') && !chatting; // Same for send button
        clearChatBtn.disabled = uploading || chatting;

        if (uploading) {
            uploadSpinner.classList.remove('hidden');
            uploadBtn.querySelector('span').textContent = 'Uploading...';
        } else {
            uploadSpinner.classList.add('hidden');
            uploadBtn.querySelector('span').textContent = 'Upload Report';
        }

        if (chatting) {
            chatSpinner.classList.remove('hidden');
            sendBtn.querySelector('span').textContent = 'Sending...';
        } else {
            chatSpinner.classList.add('hidden');
            sendBtn.querySelector('span').textContent = 'Send';
        }
    };

    // Initial UI state: allow upload, disable chat
    setUIState(false, false);

    // Function to add a message to the chat display
    const addMessage = (sender, message) => {
        const messageElement = document.createElement('div');
        messageElement.classList.add('chat-message', sender, 'p-3', 'rounded-lg', 'max-w-[85%]', 'mb-2', 'shadow-sm');
        
        // Add specific alignment for user/bot messages
        if (sender === 'user') {
            messageElement.classList.add('ml-auto', 'bg-blue-100', 'text-blue-800', 'rounded-br-none'); // User messages align right
        } else {
            messageElement.classList.add('mr-auto', 'bg-gray-100', 'text-gray-800', 'rounded-bl-none'); // Bot messages align left
        }

        // Replace newlines with <br> for proper display of multi-line text
        messageElement.innerHTML = message.replace(/\n/g, '<br>');
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight; // Scroll to bottom
    };

    // --- Report Upload Logic ---
    uploadBtn.addEventListener('click', async () => {
        const file = pdfFile.files[0];
        if (!file) {
            uploadStatus.textContent = 'Please select a PDF file.';
            uploadStatus.classList.remove('text-green-600', 'text-blue-600');
            uploadStatus.classList.add('text-red-600');
            return;
        }

        setUIState(true, false); // Set UI to uploading state
        uploadStatus.textContent = 'Uploading and processing report... This may take a moment.';
        uploadStatus.classList.remove('text-green-600', 'text-red-600');
        uploadStatus.classList.add('text-blue-600');
        
        // Clear previous chat messages except the initial bot message
        chatMessages.innerHTML = `
            <div class="chat-message bot p-3 rounded-lg max-w-[85%] mb-2 shadow-sm">
                Hello! Please upload a security report PDF to get started, or ask a general cybersecurity question.
            </div>
        `;
        summaryDisplay.classList.add('hidden'); // Hide old summary
        summaryPre.textContent = ''; // Clear old summary text

        const formData = new FormData();
        formData.append('pdf_file', file);

        try {
            const response = await fetch('/upload_report', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.success) {
                summaryPre.textContent = data.summary;
                summaryDisplay.classList.remove('hidden'); // Show summary section
                summaryDisplay.classList.add('flex'); // Make it flex for proper display
                uploadStatus.textContent = 'Report uploaded and summarized successfully!';
                uploadStatus.classList.remove('text-blue-600', 'text-red-600');
                uploadStatus.classList.add('text-green-600');
                
                // Add the initial summary to chat as a bot message
                addMessage('bot', data.summary);

                // Enable chat input after successful upload
                chatInput.disabled = false;
                sendBtn.disabled = false;
            } else {
                uploadStatus.textContent = `Error: ${data.message}`;
                uploadStatus.classList.remove('text-blue-600', 'text-green-600');
                uploadStatus.classList.add('text-red-600');
                chatInput.disabled = true; // Keep chat disabled on error
                sendBtn.disabled = true;
            }
        } catch (error) {
            console.error('Upload error:', error);
            uploadStatus.textContent = 'An unexpected error occurred during upload.';
            uploadStatus.classList.remove('text-blue-600', 'text-green-600');
            uploadStatus.classList.add('text-red-600');
            chatInput.disabled = true; // Keep chat disabled on error
            sendBtn.disabled = true;
        } finally {
            setUIState(false, false); // Reset UI state
        }
    });

    // --- Chat Logic ---
    const sendMessage = async () => {
        const message = chatInput.value.trim();
        if (message === '') {
            return;
        }

        addMessage('user', message);
        chatInput.value = ''; // Clear input field
        setUIState(false, true); // Set UI to chatting state

        try {
            const response = await fetch('/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: message })
            });

            const data = await response.json();

            if (data.success) {
                addMessage('bot', data.response);
            } else {
                addMessage('bot', `Error: ${data.message}`);
            }
        } catch (error) {
            console.error('Chat error:', error);
            addMessage('bot', 'An unexpected error occurred while communicating with the AI.');
        } finally {
            setUIState(false, false); // Reset UI state
            chatInput.focus(); // Keep focus on input
        }
    };

    sendBtn.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !sendBtn.disabled) {
            sendMessage();
        }
    });

    // --- Clear Chat and New Report Logic ---
    clearChatBtn.addEventListener('click', async () => {
        setUIState(false, true); // Temporarily show spinning for clear button
        uploadStatus.textContent = 'Clearing session...';
        uploadStatus.classList.remove('text-green-600', 'text-red-600');
        uploadStatus.classList.add('text-blue-600');

        try {
            const response = await fetch('/clear_chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            const data = await response.json();

            if (data.success) {
                uploadStatus.textContent = 'Session cleared. Ready for a new report!';
                uploadStatus.classList.remove('text-blue-600', 'text-red-600');
                uploadStatus.classList.add('text-green-600');
                
                // Reset UI elements
                pdfFile.value = ''; // Clear file input
                summaryDisplay.classList.add('hidden'); // Hide summary
                summaryPre.textContent = ''; // Clear summary text
                chatInput.disabled = true; // Disable chat input
                sendBtn.disabled = true;
                
                // Reset chat messages to initial state
                chatMessages.innerHTML = `
                    <div class="chat-message bot p-3 rounded-lg max-w-[85%] mb-2 shadow-sm">
                        Hello! Please upload a security report PDF to get started, or ask a general cybersecurity question.
                    </div>
                `;
            } else {
                uploadStatus.textContent = `Error clearing session: ${data.message}`;
                uploadStatus.classList.remove('text-blue-600', 'text-green-600');
                uploadStatus.classList.add('text-red-600');
            }
        } catch (error) {
            console.error('Clear chat error:', error);
            uploadStatus.textContent = 'An unexpected error occurred while clearing session.';
            uploadStatus.classList.remove('text-blue-600', 'text-green-600');
            uploadStatus.classList.add('text-red-600');
        } finally {
            setUIState(false, false); // Reset UI state
        }
    });
});

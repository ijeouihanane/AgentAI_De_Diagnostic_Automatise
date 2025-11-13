const submitBtn = document.getElementById('submitBtn');
const promptInput = document.getElementById('prompt');
const progressBar = document.querySelector('.progress-bar');
const statusText = document.getElementById('status');
const resultsTableContainer = document.getElementById('resultsTableContainer');
const progressContainer = document.getElementById('progress');

const exportButtonsContainer = document.querySelector('.export-buttons');
const exportCsvBtn = document.getElementById('exportCsvBtn');
const exportExcelBtn = document.getElementById('exportExcelBtn');

const newConversationBtn = document.getElementById('newConversationBtn');
const conversationList = document.getElementById('conversationList');
const chatMessagesContainer = document.getElementById('chatMessages');

const welcomeScreen = document.getElementById('welcomeScreen');
const chatInterface = document.getElementById('chatInterface');
const suggestionCards = document.querySelectorAll('.suggestion-cards .card');

let currentConversationId = null;

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

async function typewriter(el, text, speed = 8) {
    el.textContent = '';
    for (let i = 0; i < text.length; i++) {
        el.textContent += text[i];
        if (i % 3 === 0) await sleep(speed);
    }
}

async function run(inputPrompt = null) {
    const prompt = inputPrompt || promptInput.value.trim();
    if (!prompt) return;

    // Hide welcome screen, show chat interface
    welcomeScreen.style.display = 'none';
    chatInterface.style.display = 'flex'; // Use flex to maintain column layout

    submitBtn.classList.add('loading');
    // progressContainer.classList.add('active'); // Will be activated by individual progress updates
    progressBar.style.width = '0%';
    statusText.textContent = 'Lecture du prompt…';
    progressContainer.style.visibility = 'visible'; // Show progress bar container
    progressContainer.style.opacity = '1';


    resultsTableContainer.innerHTML = '';
    exportButtonsContainer.style.display = 'none';

    try {
        // Step 1: Add user message to conversation immediately
        await addMessageToCurrentConversation('user', prompt);
        
        // Step 2: Trigger AI processing and SQL generation
        progressBar.style.width = '20%';
        statusText.textContent = 'Génération de la requête SQL…';
        
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt, conversation_id: currentConversationId })
        });

        const data = await response.json();

        if (data.conversation_id && data.conversation_id !== currentConversationId) {
            currentConversationId = data.conversation_id;
            await loadConversations(); // Reload conversations to update sidebar and select new one
        }
        
        // Check if response is HTML (indicating an error not handled by Flask jsonify)
        if (typeof data === 'string' && data.startsWith('<!doctype html>')) {
             throw new Error("Backend returned HTML, likely an unhandled Flask error.");
        }

        if (data.status === 'success') {
            progressBar.style.width = '100%';
            statusText.textContent = 'Terminé';

            // Display AI response message
            await addMessageToCurrentConversation('ai', 'Requête exécutée.', data.sql, data.results);

            if (data.results && data.results.length > 0) {
                displayResultsAsTable(data.results);
                exportButtonsContainer.style.display = 'flex';
            } else {
                resultsTableContainer.innerHTML = '<p class="info-message">Aucun résultat trouvé.</p>';
                exportButtonsContainer.style.display = 'none';
            }
            
        } else {
            statusText.textContent = 'Erreur';
            resultsTableContainer.innerHTML = `<p class="error-message">${data.message || 'Une erreur est survenue.'}</p>`;
            exportButtonsContainer.style.display = 'none';
            await addMessageToCurrentConversation('ai', data.message || 'Une erreur est survenue.');
        }
    } catch (err) {
        console.error("Run function caught an error:", err);
        statusText.textContent = 'Erreur';
        resultsTableContainer.innerHTML = `<p class="error-message">${err?.message || String(err)}</p>`;
        exportButtonsContainer.style.display = 'none';
        await addMessageToCurrentConversation('ai', `Erreur inattendue: ${err?.message || String(err)}`);
    } finally {
        submitBtn.classList.remove('loading');
        progressContainer.style.opacity = '0'; // Hide progress bar
        progressContainer.style.visibility = 'hidden';
        promptInput.value = ''; // Clear prompt input after submission
    }
}

submitBtn.addEventListener('click', () => run());
promptInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        run();
    }
});

suggestionCards.forEach(card => {
    card.addEventListener('click', () => {
        const prompt = card.dataset.prompt;
        run(prompt); // Run the analysis with the card's prompt
    });
});


function displayResultsAsTable(results) {
    resultsTableContainer.innerHTML = '';

    if (!results || results.length === 0) {
        resultsTableContainer.innerHTML = '<p class="info-message">Aucun résultat trouvé.</p>';
        return;
    }

    const table = document.createElement('table');
    table.classList.add('results-table');

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    Object.keys(results[0]).forEach(key => {
        const th = document.createElement('th');
        th.textContent = key;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    results.forEach(row => {
        const tr = document.createElement('tr');
        Object.values(row).forEach(value => {
            const td = document.createElement('td');
            td.textContent = value;
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    resultsTableContainer.appendChild(table);

    exportCsvBtn.dataset.results = JSON.stringify(results);
    exportExcelBtn.dataset.results = JSON.stringify(results);
}

// --- Fonctions d'exportation ---
exportCsvBtn.addEventListener('click', () => {
    const results = JSON.parse(exportCsvBtn.dataset.results);
    if (!results || results.length === 0) return;

    const headers = Object.keys(results[0]);
    const csv = [headers.join(',')];
    results.forEach(row => {
        const values = headers.map(header => {
            let value = row[header];
            if (typeof value === 'string') {
                value = `"${value.replace(/"/g, '""')}"`; // Proper CSV escaping
            }
            return value;
        });
        csv.push(values.join(','));
    });

    const csvBlob = new Blob([csv.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const csvUrl = URL.createObjectURL(csvBlob);
    const link = document.createElement('a');
    link.setAttribute('href', csvUrl);
    link.setAttribute('download', 'results.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
});

exportExcelBtn.addEventListener('click', () => {
    const results = JSON.parse(exportExcelBtn.dataset.results);
    if (!results || results.length === 0) return;

    const headers = Object.keys(results[0]);
    const csv = [headers.join(',')];
    results.forEach(row => {
        const values = headers.map(header => {
            let value = row[header];
            if (typeof value === 'string') {
                value = `"${value.replace(/"/g, '""')}"`; // Proper CSV escaping
            }
            return value;
        });
        csv.push(values.join(','));
    });

    const excelBlob = new Blob([csv.join('\n')], { type: 'application/vnd.ms-excel;charset=utf-8;' });
    const excelUrl = URL.createObjectURL(excelBlob);
    const link = document.createElement('a');
    link.setAttribute('href', excelUrl);
    link.setAttribute('download', 'results.xls');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
});

// --- Conversation Management Logic ---
async function loadConversations() {
    try {
        const response = await fetch('/conversations');
        const data = await response.json();
        if (data.status === 'success') {
            conversationList.innerHTML = '';
            data.conversations.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

            if (data.conversations.length > 0) {
                data.conversations.forEach(conv => {
                    const li = document.createElement('li');
                    li.dataset.conversationId = conv.id;
                    li.textContent = conv.title;
                    li.classList.add('conversation-item');
                    li.addEventListener('click', () => selectConversation(conv.id, conv.title));

                    const deleteBtn = document.createElement('button');
                    deleteBtn.textContent = 'X';
                    deleteBtn.classList.add('delete-conversation-btn');
                    deleteBtn.addEventListener('click', async (e) => {
                        e.stopPropagation();
                        await deleteConversation(conv.id);
                    });
                    li.appendChild(deleteBtn);
                    conversationList.appendChild(li);
                });

                if (!currentConversationId || !data.conversations.some(conv => conv.id === currentConversationId)) {
                    const latestConversation = data.conversations[0];
                    await selectConversation(latestConversation.id, latestConversation.title);
                } else {
                    const activeItem = document.querySelector(`.conversation-item[data-conversation-id="${currentConversationId}"]`);
                    if (activeItem) { activeItem.classList.add('active'); }
                    await loadConversationMessages(currentConversationId);
                }
            } else {
                // If no conversations, show welcome screen
                welcomeScreen.style.display = 'flex';
                chatInterface.style.display = 'none';
                resultsTableContainer.innerHTML = '<p class="info-message">Aucune conversation trouvée. Créez-en une nouvelle pour commencer !</p>';
                displayMessages([]);
                currentConversationId = null;
            }
        } else {
            console.error('Erreur lors du chargement des conversations:', data.message);
        }
    } catch (error) {
        console.error('Failed to fetch conversations:', error);
    }
}


async function createNewConversation() {
    try {
        // This button now creates a conversation with a default title.
        // The /analyze route will update the title with an AI-generated one if it's the first prompt.
        const response = await fetch('/conversations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title: "Nouvelle Conversation" }) 
        });
        const data = await response.json();
        if (data.status === 'success') {
            await loadConversations(); // Reloads and selects the new conversation
        } else {
            console.error('Erreur lors de la création de la conversation:', data.message);
        }
    } catch (error) {
        console.error('Failed to create new conversation:', error);
    }
}

async function selectConversation(conversationId, title) {
    currentConversationId = conversationId;
    document.querySelectorAll('.conversation-item').forEach(item => {
        item.classList.remove('active');
    });
    const activeItem = document.querySelector(`.conversation-item[data-conversation-id="${conversationId}"]`);
    if (activeItem) activeItem.classList.add('active');
    
    welcomeScreen.style.display = 'none';
    chatInterface.style.display = 'flex';

    await loadConversationMessages(conversationId);
}

async function loadConversationMessages(convId) {
    try {
        const response = await fetch(`/conversations/${convId}`);
        const data = await response.json();
        if (data.status === 'success' && data.messages) {
            displayMessages(data.messages);
            promptInput.value = '';
        } else {
            console.error('Erreur lors du chargement des messages de la conversation:', data.message);
            displayMessages([]);
        }
    } catch (error) {
        console.error('Failed to fetch messages:', error);
    }
}

async function deleteConversation(convId) {
    if (!confirm('Voulez-vous vraiment supprimer cette conversation ?')) return;
    try {
        const response = await fetch(`/conversations/${convId}`, {
            method: 'DELETE'
        });
        const data = await response.json();
        if (data.status === 'success') {
            console.log(data.message);
            currentConversationId = null;
            await loadConversations(); 
        } else {
            console.error('Error deleting conversation:', data.message);
        }
    } catch (error) {
        console.error('Failed to delete conversation:', error);
    }
}

function displayMessages(messages) {
    chatMessagesContainer.innerHTML = '';
    messages.forEach(msg => {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message-item');
        messageDiv.classList.add(msg.sender === 'user' ? 'user-message' : 'ai-message');
        messageDiv.innerHTML = `<strong>${msg.sender === 'user' ? 'Vous' : 'IA'}:</strong> ${msg.content}`;
        chatMessagesContainer.appendChild(messageDiv);
    });
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
}

async function addMessageToCurrentConversation(sender, content, sql_query = null, results = null) {
    if (!currentConversationId) {
        // This should ideally not happen if loadConversations correctly creates/selects one.
        console.error("No active conversation to add message to. Cannot save message.");
        return; 
    }
    fetch(`/conversations/${currentConversationId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, content, sql_query, results })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            loadConversationMessages(currentConversationId); // Reload to show new message
        } else {
            console.error('Erreur lors de l\'ajout du message:', data.message);
        }
    })
    .catch(error => {
        console.error('Failed to add message to conversation:', error);
    });
}

// Initial load
document.addEventListener('DOMContentLoaded', async () => {
    await loadConversations();
    newConversationBtn.addEventListener('click', createNewConversation);
});
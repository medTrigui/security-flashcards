// Flash Cards Application Logic
class FlashCardsApp {
    constructor() {
        this.currentCategory = 'networking';
        this.currentCardIndex = 0;
        this.isFlipped = false;
        this.shuffledCards = [];
        
        this.initializeApp();
        this.bindEvents();
        this.loadCategory(this.currentCategory);
    }
    
    initializeApp() {
        // Get DOM elements
        this.flashcard = document.getElementById('flashcard');
        this.questionText = document.getElementById('question-text');
        this.answerText = document.getElementById('answer-text');
        this.currentCardSpan = document.getElementById('current-card');
        this.totalCardsSpan = document.getElementById('total-cards');
        this.progressFill = document.querySelector('.progress-fill');
        this.prevBtn = document.getElementById('prev-btn');
        this.nextBtn = document.getElementById('next-btn');
        this.shuffleBtn = document.getElementById('shuffle-btn');
        this.resetBtn = document.getElementById('reset-btn');
        this.categoryBtns = document.querySelectorAll('.category-btn');
    }
    
    bindEvents() {
        // Flashcard flip event
        this.flashcard.addEventListener('click', () => this.flipCard());
        
        // Navigation events
        this.prevBtn.addEventListener('click', () => this.previousCard());
        this.nextBtn.addEventListener('click', () => this.nextCard());
        
        // Utility events
        this.shuffleBtn.addEventListener('click', () => this.shuffleCards());
        this.resetBtn.addEventListener('click', () => this.resetProgress());
        
        // Category selection events
        this.categoryBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const category = e.target.dataset.category;
                this.switchCategory(category);
            });
        });
        
        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            switch(e.key) {
                case ' ':
                case 'Enter':
                    e.preventDefault();
                    this.flipCard();
                    break;
                case 'ArrowLeft':
                    e.preventDefault();
                    this.previousCard();
                    break;
                case 'ArrowRight':
                    e.preventDefault();
                    this.nextCard();
                    break;
            }
        });
    }
    
    loadCategory(category) {
        this.currentCategory = category;
        this.currentCardIndex = 0;
        this.isFlipped = false;
        
        // Get cards for this category
        const cards = window.flashcardsData[category] || [];
        this.shuffledCards = [...cards]; // Copy array
        
        this.updateCategoryButtons();
        this.updateCard();
        this.updateProgress();
        this.updateNavigationButtons();
    }
    
    switchCategory(category) {
        if (category !== this.currentCategory) {
            this.loadCategory(category);
        }
    }
    
    updateCategoryButtons() {
        this.categoryBtns.forEach(btn => {
            btn.classList.toggle('active', btn.dataset.category === this.currentCategory);
        });
    }
    
    flipCard() {
        this.isFlipped = !this.isFlipped;
        this.flashcard.classList.toggle('flipped', this.isFlipped);
    }
    
    updateCard() {
        if (this.shuffledCards.length === 0) {
            this.questionText.textContent = 'No cards available for this category';
            this.answerText.textContent = 'Please select a different category';
            return;
        }
        
        const currentCard = this.shuffledCards[this.currentCardIndex];
        this.questionText.textContent = currentCard.question;
        this.answerText.textContent = currentCard.answer;
        
        // Reset flip state
        this.isFlipped = false;
        this.flashcard.classList.remove('flipped');
    }
    
    updateProgress() {
        const total = this.shuffledCards.length;
        const current = this.currentCardIndex + 1;
        
        this.currentCardSpan.textContent = current;
        this.totalCardsSpan.textContent = total;
        
        const progressPercent = total > 0 ? (current / total) * 100 : 0;
        this.progressFill.style.width = `${progressPercent}%`;
    }
    
    updateNavigationButtons() {
        this.prevBtn.disabled = this.currentCardIndex === 0;
        this.nextBtn.disabled = this.currentCardIndex >= this.shuffledCards.length - 1;
    }
    
    previousCard() {
        if (this.currentCardIndex > 0) {
            this.currentCardIndex--;
            this.updateCard();
            this.updateProgress();
            this.updateNavigationButtons();
        }
    }
    
    nextCard() {
        if (this.currentCardIndex < this.shuffledCards.length - 1) {
            this.currentCardIndex++;
            this.updateCard();
            this.updateProgress();
            this.updateNavigationButtons();
        }
    }
    
    shuffleCards() {
        // Fisher-Yates shuffle algorithm
        for (let i = this.shuffledCards.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [this.shuffledCards[i], this.shuffledCards[j]] = [this.shuffledCards[j], this.shuffledCards[i]];
        }
        
        this.currentCardIndex = 0;
        this.updateCard();
        this.updateProgress();
        this.updateNavigationButtons();
    }
    
    resetProgress() {
        this.currentCardIndex = 0;
        this.isFlipped = false;
        
        // Reset to original order
        const originalCards = window.flashcardsData[this.currentCategory] || [];
        this.shuffledCards = [...originalCards];
        
        this.updateCard();
        this.updateProgress();
        this.updateNavigationButtons();
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new FlashCardsApp();
});

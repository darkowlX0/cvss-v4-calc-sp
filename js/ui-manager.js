// UI Manager para la calculadora CVSS v4.0
// Maneja toda la interacción con la interfaz de usuario

class CVSSUIManager {
    constructor() {
        this.form = null;
        this.scoreValue = null;
        this.scoreLabel = null;
        this.severityLevel = null;
        this.vectorString = null;
        this.baseScore = null;
        this.threatScore = null;
        this.envScore = null;
        this.resetBtn = null;
        this.copyBtn = null;
        this.isInitialized = false;

        // Bind methods to preserve context
        this.handleInputChange = this.handleInputChange.bind(this);
        this.handleReset = this.handleReset.bind(this);
        this.handleCopy = this.handleCopy.bind(this);
        this.updateDisplay = this.updateDisplay.bind(this);
    }

    // Inicializa el UI Manager
    init() {
        if (this.isInitialized) return;

        this.form = document.getElementById('cvssForm');
        this.scoreValue = document.getElementById('scoreValue');
        this.scoreLabel = document.getElementById('scoreLabel');
        this.severityLevel = document.getElementById('severityLevel');
        this.vectorString = document.getElementById('vectorString');
        this.baseScore = document.getElementById('baseScore');
        this.threatScore = document.getElementById('threatScore');
        this.envScore = document.getElementById('envScore');
        this.resetBtn = document.getElementById('resetBtn');
        this.copyBtn = document.getElementById('copyBtn');

        if (!this.form || !this.scoreValue || !this.severityLevel || !this.vectorString) {
            console.error('Elementos requeridos no encontrados en el DOM');
            return;
        }

        this.setupEventListeners();
        this.updateDisplay(); // Actualización inicial
        this.isInitialized = true;

        console.log('CVSS UI Manager inicializado correctamente');
    }

    // Configura los event listeners
    setupEventListeners() {
        // Event listeners para inputs de radio
        const radioInputs = this.form.querySelectorAll('input[type="radio"]');
        radioInputs.forEach(input => {
            input.addEventListener('change', this.handleInputChange);
        });

        // Event listeners para botones
        if (this.resetBtn) {
            this.resetBtn.addEventListener('click', this.handleReset);
        }

        if (this.copyBtn) {
            this.copyBtn.addEventListener('click', this.handleCopy);
        }
    }

    // Maneja cambios en los inputs
    handleInputChange(event) {
        const metric = event.target.name;
        const value = event.target.value;

        if (metric && value) {
            // Actualizar el calculador
            cvssCalculator.updateMetrics({ [metric]: value });
            
            // Actualizar la visualización
            this.updateDisplay();
            
            // Remover clase de error si existe
            const metricRow = event.target.closest('.metric-row');
            if (metricRow) {
                metricRow.classList.remove('invalid');
                const errorMessage = metricRow.querySelector('.validation-message');
                if (errorMessage) {
                    errorMessage.remove();
                }
            }
        }
    }

    // Maneja el reset del formulario
    handleReset() {
        // Reiniciar el calculador
        cvssCalculator.reset();
        
        // Limpiar todos los inputs de radio
        const radioInputs = this.form.querySelectorAll('input[type="radio"]');
        radioInputs.forEach(input => {
            input.checked = false;
        });

        // Remover todas las clases de error
        const metricRows = this.form.querySelectorAll('.metric-row');
        metricRows.forEach(row => {
            row.classList.remove('invalid');
            const errorMessage = row.querySelector('.validation-message');
            if (errorMessage) {
                errorMessage.remove();
            }
        });

        // Actualizar la visualización
        this.updateDisplay();
    }

    // Maneja la copia del vector string
    async handleCopy() {
        const result = cvssCalculator.calculateComplete();
        const textToCopy = result.vectorString;

        try {
            await navigator.clipboard.writeText(textToCopy);
            
            // Feedback visual
            const originalText = this.copyBtn.textContent;
            this.copyBtn.textContent = 'Copiado!';
            this.copyBtn.style.background = '#27ae60';
            
            setTimeout(() => {
                this.copyBtn.textContent = originalText;
                this.copyBtn.style.background = '';
            }, 2000);
            
        } catch (err) {
            console.error('Error al copiar:', err);
            
            // Fallback para navegadores sin soporte
            const textArea = document.createElement('textarea');
            textArea.value = textToCopy;
            document.body.appendChild(textArea);
            textArea.select();
            
            try {
                document.execCommand('copy');
                const originalText = this.copyBtn.textContent;
                this.copyBtn.textContent = 'Copiado!';
                setTimeout(() => {
                    this.copyBtn.textContent = originalText;
                }, 2000);
            } catch (fallbackErr) {
                console.error('Error en fallback de copia:', fallbackErr);
            }
            
            document.body.removeChild(textArea);
        }
    }

    // Actualiza la visualización de resultados
    updateDisplay() {
        const result = cvssCalculator.calculateComplete();

        // Actualizar score principal con animación
        if (this.scoreValue) {
            this.scoreValue.classList.add('score-updating');
            setTimeout(() => {
                this.scoreValue.textContent = result.score.toFixed(1);
                this.scoreValue.classList.remove('score-updating');
            }, 150);
        }

        // Actualizar etiqueta del score
        if (this.scoreLabel) {
            this.scoreLabel.textContent = `${result.scoreType} Score`;
        }

        // Actualizar desglose de scores
        if (this.baseScore) {
            this.baseScore.textContent = result.baseScore.toFixed(1);
        }
        if (this.threatScore) {
            this.threatScore.textContent = result.threatScore.toFixed(1);
        }
        if (this.envScore) {
            this.envScore.textContent = result.environmentalScore.toFixed(1);
        }

        // Actualizar nivel de severidad
        if (this.severityLevel) {
            this.severityLevel.textContent = result.severity.level;
            this.severityLevel.className = `severity-level ${result.severity.class}`;
        }

        // Actualizar vector string
        if (this.vectorString) {
            this.vectorString.textContent = result.vectorString;
        }

        // Mostrar errores de validación si existen
        this.showValidationErrors(result);

        // Actualizar estado de botones
        this.updateButtonStates(result);
    }

    // Muestra errores de validación
    showValidationErrors(result) {
        if (result.missingMetrics.length > 0) {
            result.missingMetrics.forEach(metric => {
                const input = this.form.querySelector(`input[name="${metric}"]`);
                if (input) {
                    const metricRow = input.closest('.metric-row');
                    if (metricRow && !metricRow.classList.contains('invalid')) {
                        metricRow.classList.add('invalid');
                        
                        // Agregar mensaje de error si no existe
                        if (!metricRow.querySelector('.validation-message')) {
                            const errorMessage = document.createElement('div');
                            errorMessage.className = 'validation-message';
                            errorMessage.textContent = `Por favor selecciona un valor para ${metricNames[metric]}`;
                            metricRow.appendChild(errorMessage);
                        }
                    }
                }
            });
        }
    }

    // Actualiza el estado de los botones
    updateButtonStates(result) {
        if (this.copyBtn) {
            this.copyBtn.disabled = !result.isComplete;
            if (!result.isComplete) {
                this.copyBtn.classList.add('disabled');
            } else {
                this.copyBtn.classList.remove('disabled');
            }
        }
    }

    // Obtiene las métricas actuales del formulario
    getCurrentMetrics() {
        const metrics = {};
        const radioInputs = this.form.querySelectorAll('input[type="radio"]:checked');
        
        radioInputs.forEach(input => {
            metrics[input.name] = input.value;
        });
        
        return metrics;
    }

    // Establece las métricas en el formulario
    setMetrics(metrics) {
        Object.entries(metrics).forEach(([metric, value]) => {
            const input = this.form.querySelector(`input[name="${metric}"][value="${value}"]`);
            if (input) {
                input.checked = true;
            }
        });
        
        // Actualizar el calculador
        cvssCalculator.updateMetrics(metrics);
        this.updateDisplay();
    }

    // Importa un vector string CVSS
    importVectorString(vectorString) {
        try {
            // Parsear el vector string
            const parts = vectorString.split('/');
            
            if (parts[0] !== 'CVSS:4.0') {
                throw new Error('Vector string no es CVSS v4.0');
            }
            
            const metrics = {};
            for (let i = 1; i < parts.length; i++) {
                const [metric, value] = parts[i].split(':');
                if (metric && value && value !== '_') {
                    metrics[metric] = value;
                }
            }
            
            // Validar métricas
            Object.entries(metrics).forEach(([metric, value]) => {
                if (!cvssCalculator.isValidValue(metric, value)) {
                    throw new Error(`Valor inválido para ${metric}: ${value}`);
                }
            });
            
            // Aplicar métricas
            this.handleReset(); // Limpiar primero
            this.setMetrics(metrics);
            
            return true;
        } catch (error) {
            console.error('Error al importar vector string:', error);
            alert(`Error al importar vector string: ${error.message}`);
            return false;
        }
    }
}

// Instancia global del UI Manager
const uiManager = new CVSSUIManager();

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    uiManager.init();
});

// Función global para importar vector string (útil para debugging)
window.importCVSSVector = (vectorString) => {
    return uiManager.importVectorString(vectorString);
};

// Función global para obtener el estado actual (útil para debugging)
window.getCurrentCVSSState = () => {
    return cvssCalculator.calculateComplete();
};
# Calculadora CVSS v4.0

Una implementación completa en español de la **Calculadora de Sistema Común de Puntuación de Vulnerabilidades (CVSS) versión 4.0**, basada en la especificación oficial de FIRST (Forum of Incident Response and Security Teams).

## Características

- ✅ **Implementación oficial**: Basada en la especificación CVSS v4.0 de FIRST
- ✅ **Cálculo preciso**: Utiliza la tabla de lookup oficial y algoritmo de MacroVectors
- ✅ **Interfaz moderna**: Diseño responsive y amigable al usuario
- ✅ **Tiempo real**: Cálculo automático mientras completas las métricas
- ✅ **Validación completa**: Verificación de entradas y mensajes de error claros
- ✅ **Vector String**: Generación automática del vector CVSS v4.0
- ✅ **Multiidioma**: Interfaz completamente en español

## Métricas CVSS v4.0 Completas

La calculadora incluye **TODAS** las métricas CVSS v4.0 organizadas en 4 grupos:

### Métricas de Explotabilidad
- **Vector de Ataque (AV)**: Remoto, Adyacente, Local, Físico
- **Complejidad de Ataque (AC)**: Baja, Alta
- **Requerimientos de Ataque (AT)**: Ninguno, Presente *(Nuevo en v4.0)*
- **Privilegios Requeridos (PR)**: Ninguno, Bajo, Alto
- **Interacción de Usuario (UI)**: Ninguna, Pasiva, Activa

### Métricas de Impacto del Sistema Vulnerable
- **Confidencialidad (VC)**: Alto, Bajo, Ninguno
- **Integridad (VI)**: Alto, Bajo, Ninguno
- **Disponibilidad (VA)**: Alto, Bajo, Ninguno

### Métricas de Impacto del Sistema Subsecuente *(Nuevo en v4.0)*
- **Confidencialidad (SC)**: Alto, Bajo, Ninguno
- **Integridad (SI)**: Alto, Bajo, Ninguno
- **Disponibilidad (SA)**: Alto, Bajo, Ninguno

### Métricas de Amenaza *(Threat)*
- **Madurez del Exploit (E)**: No Definido, Atacado, Prueba de Concepto, No Probado

### Métricas Ambientales *(Environmental)*
#### Requisitos de Seguridad
- **Requisito de Confidencialidad (CR)**: No Definido, Alto, Medio, Bajo
- **Requisito de Integridad (IR)**: No Definido, Alto, Medio, Bajo  
- **Requisito de Disponibilidad (AR)**: No Definido, Alto, Medio, Bajo

#### Métricas Base Modificadas
- **Vector de Ataque Modificado (MAV)**: No Definido, Remoto, Adyacente, Local, Físico
- **Complejidad de Ataque Modificada (MAC)**: No Definido, Baja, Alta
- **Requerimientos de Ataque Modificados (MAT)**: No Definido, Ninguno, Presente
- **Privilegios Requeridos Modificados (MPR)**: No Definido, Ninguno, Bajo, Alto
- **Interacción de Usuario Modificada (MUI)**: No Definido, Ninguna, Pasiva, Activa
- **Impactos Modificados (MVC/MVI/MVA/MSC/MSI/MSA)**: No Definido, Alto, Bajo, Ninguno

### Métricas Suplementarias *(No afectan el score)*
- **Seguridad (S)**: No Definido, Sin Impacto, Presente
- **Automatizable (AU)**: No Definido, No, Sí
- **Recuperación (R)**: No Definido, Automática, Usuario, Irrecuperable
- **Densidad de Valor (V)**: No Definido, Difusa, Concentrada
- **Esfuerzo de Respuesta (RE)**: No Definido, Bajo, Medio, Alto
- **Urgencia del Proveedor (U)**: No Definido, Claro, Verde, Ámbar, Rojo

## 🛠 Instalación y Uso

### Método 1: Servidor Local
```bash
# Clonar o descargar el proyecto
cd CVSSCALC

# Iniciar servidor HTTP local (Python 3)
python3 -m http.server 8000

# Abrir en navegador
open http://localhost:8000
```

### Método 2: Directamente desde archivo
Simplemente abre `index.html` en tu navegador web.

## Cómo usar la calculadora

1. **Completa las métricas base**: Selecciona valores para las 11 métricas base obligatorias
2. **Añade métricas opcionales**: 
   - **Threat**: Para considerar madurez del exploit
   - **Environmental**: Para personalizar según tu entorno
   - **Supplemental**: Para contexto adicional (no afecta el score)
3. **Observa los resultados**: La calculadora muestra automáticamente:
   - **Base Score**: Score fundamental de la vulnerabilidad
   - **Threat Score**: Base + métricas de amenaza
   - **Environmental Score**: Score personalizado para tu entorno
   - **Score Principal**: El más relevante según las métricas completadas
4. **Copia el vector**: Vector string completo con todas las métricas
5. **Reinicia si necesario**: Limpia todas las selecciones

### Niveles de Severidad

| Score | Nivel | Color |
|-------|-------|-------|
| 0.0 | Ninguno | Gris |
| 0.1 - 3.9 | Bajo | Verde |
| 4.0 - 6.9 | Medio | Naranja |
| 7.0 - 8.9 | Alto | Rojo |
| 9.0 - 10.0 | Crítico | Púrpura |

## Verificación y Precisión

La implementación ha sido verificada contra:
- ✅ Ejemplos oficiales de FIRST
- ✅ Calculadora de referencia de NIST
- ✅ Casos de prueba del repositorio oficial

Para ejecutar las pruebas de verificación, abre `test-vectors.html` en tu navegador.

## Arquitectura Técnica

### Estructura del Proyecto
```
CVSSCALC/
├── index.html          # Página principal
├── test-vectors.html   # Verificación de cálculos
├── styles/
│   └── main.css       # Estilos modernos y responsive
├── js/
│   ├── cvss-data.js   # Lookup tables y configuraciones
│   ├── cvss-calculator.js  # Lógica de cálculo CVSS v4.0
│   └── ui-manager.js  # Gestión de interfaz de usuario
└── README.md          # Esta documentación
```

### Algoritmo de Cálculo

La calculadora implementa el algoritmo oficial CVSS v4.0:

1. **Validación**: Verifica que todas las métricas base estén presentes
2. **MacroVector**: Reduce las 32 dimensiones a 6 ecuaciones (EQ1-EQ6)
3. **Lookup**: Obtiene el score base de la tabla oficial
4. **Interpolación**: Aplica ajustes basados en distancias de severidad
5. **Redondeo**: Aplica el redondeo oficial a 1 decimal

### Tecnologías Utilizadas

- **HTML5**: Estructura semántica y accesible
- **CSS3**: Diseño moderno con Grid/Flexbox
- **JavaScript ES6+**: Lógica de cálculo sin dependencias
- **Design System**: Inspirado en Material Design

## Casos de Prueba

La calculadora incluye verificación automática contra estos casos oficiales:

### CVE-2022-41741
```
Vector: CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
Score Esperado: 7.3
```

### CVE-2020-3549 (Base)
```
Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
Score Base Estimado: ~8.7
```

### Caso Sin Impacto
```
Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
Score: 0.0
```

## API JavaScript

La calculadora expone una API JavaScript para uso programático:

```javascript
// Calcular score para métricas específicas
const metrics = {
    AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
    VC: "H", VI: "H", VA: "H", SC: "H", SI: "H", SA: "H"
};

const result = cvssCalculator.calculateComplete(metrics);
console.log(`Score: ${result.score}`);
console.log(`Vector: ${result.vectorString}`);
console.log(`Severidad: ${result.severity.level}`);

// Importar vector string
window.importCVSSVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");

// Obtener estado actual
const currentState = window.getCurrentCVSSState();
```

## Referencias

- [CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/specification-document)
- [FIRST CVSS v4.0 Calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator)
- [NIST CVSS v4.0 Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator)
- [CVSS v4.0 Examples](https://www.first.org/cvss/examples)

## Licencia

Este proyecto está inspirado en la implementación oficial de FIRST y mantiene compatibilidad con la licencia BSD-2-Clause del proyecto original.

## Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Verifica que los cálculos sigan siendo precisos
2. Mantén la compatibilidad con la especificación oficial
3. Asegúrate de que las pruebas pasen
4. Documenta cualquier cambio significativo

## Soporte

Para reportar problemas o sugerir mejoras, por favor abre un issue en el repositorio del proyecto.

---

**Nota**: Esta implementación es para fines educativos y de evaluación de vulnerabilidades. Para uso en producción crítica, siempre verifica contra la calculadora oficial de FIRST.# cvss-v4-calc-sp

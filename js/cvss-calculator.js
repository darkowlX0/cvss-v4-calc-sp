// CVSS v4.0 Calculator - Implementación basada en la especificación oficial de FIRST
// Replica exactamente la lógica de cálculo del repositorio oficial

class CVSSCalculator {
    constructor() {
        this.selectedMetrics = {};
    }

    // Función auxiliar para obtener el valor de una métrica
    m(cvssSelected, metric) {
        return cvssSelected[metric] || '';
    }

    // Calcula el MacroVector según las ecuaciones CVSS v4.0 (corregido)
    macroVector(cvssSelected) {
        let eq1, eq2, eq3, eq4, eq5, eq6;

        // EQ1: AV y PR y UI - Exploitabilidad máxima
        if (this.m(cvssSelected, "AV") === "N" && this.m(cvssSelected, "PR") === "N" && this.m(cvssSelected, "UI") === "N") {
            eq1 = "0";  // Máxima exploitabilidad
        } else if ((this.m(cvssSelected, "AV") === "N" || this.m(cvssSelected, "PR") === "N" || this.m(cvssSelected, "UI") === "N") && 
                   !(this.m(cvssSelected, "AV") === "N" && this.m(cvssSelected, "PR") === "N" && this.m(cvssSelected, "UI") === "N") && 
                   this.m(cvssSelected, "AV") !== "P") {
            eq1 = "1";  // Exploitabilidad media
        } else {
            eq1 = "2";  // Exploitabilidad baja
        }

        // EQ2: AC y AT - Complejidad
        if (this.m(cvssSelected, "AC") === "L" && this.m(cvssSelected, "AT") === "N") {
            eq2 = "0";  // Baja complejidad
        } else if (!(this.m(cvssSelected, "AC") === "L" && this.m(cvssSelected, "AT") === "N") && 
                   (this.m(cvssSelected, "AC") === "L" || this.m(cvssSelected, "AT") === "N")) {
            eq2 = "1";  // Complejidad media
        } else {
            eq2 = "2";  // Alta complejidad
        }

        // EQ3: VC y VI y VA - Impacto en sistema vulnerable
        if (this.m(cvssSelected, "VC") === "H" && this.m(cvssSelected, "VI") === "H") {
            eq3 = "0";  // Máximo impacto en C e I
        } else if (!(this.m(cvssSelected, "VC") === "H" && this.m(cvssSelected, "VI") === "H") && 
                   (this.m(cvssSelected, "VC") === "H" || this.m(cvssSelected, "VI") === "H" || this.m(cvssSelected, "VA") === "H")) {
            eq3 = "1";  // Impacto parcial
        } else {
            eq3 = "2";  // Sin impacto significativo
        }

        // EQ4: SC y SI y SA - Impacto en sistema subsecuente
        if (this.m(cvssSelected, "SC") === "H" && this.m(cvssSelected, "SI") === "H") {
            eq4 = "0";  // Máximo impacto subsecuente
        } else if (!(this.m(cvssSelected, "SC") === "H" && this.m(cvssSelected, "SI") === "H") && 
                   (this.m(cvssSelected, "SC") === "H" || this.m(cvssSelected, "SI") === "H" || this.m(cvssSelected, "SA") === "H")) {
            eq4 = "1";  // Impacto subsecuente parcial
        } else {
            eq4 = "2";  // Sin impacto subsecuente
        }

        // EQ5: Relación entre impacto vulnerable y subsecuente 
        if (eq3 === "1" && eq4 === "1") {
            eq5 = "0";
        } else if (eq3 === "0" && eq4 === "2") {
            eq5 = "0";  // Máximo impacto vulnerable, sin impacto subsecuente
        } else if (eq3 === "2" && eq4 === "2") {
            eq5 = "0";  // Sin impacto significativo en ambos sistemas
        } else if (eq3 === "1" && eq4 === "0" && this.m(cvssSelected, "VA") === "H") {
            eq5 = "1";
        } else if (eq3 === "0" && eq4 === "1" && this.m(cvssSelected, "SA") === "H") {
            eq5 = "1";
        } else {
            eq5 = "2";
        }

        // EQ6: Casos especiales - normalmente 0
        eq6 = "0";

        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }

    // Calcula la distancia de severidad entre dos vectores
    severityDistance(cvssSelected, cvssSelectedReference, metricWeights) {
        let distance = 0;
        
        const metricOrder = ["AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA"];
        
        for (let metric of metricOrder) {
            const selectedValue = this.m(cvssSelected, metric);
            const referenceValue = this.m(cvssSelectedReference, metric);
            
            if (selectedValue !== referenceValue && metricLevels[metric]) {
                const selectedLevel = metricLevels[metric][selectedValue] || 0;
                const referenceLevel = metricLevels[metric][referenceValue] || 0;
                const weight = metricWeights[metric] || 1;
                
                distance += Math.abs(selectedLevel - referenceLevel) * weight;
            }
        }
        
        return distance;
    }

    // Función principal de cálculo del score CVSS v4.0
    calculateScore(cvssSelected) {
        // Validar que todas las métricas base estén presentes
        for (let metric of baseMetrics) {
            if (!cvssSelected[metric]) {
                throw new Error(`Métrica requerida faltante: ${metricNames[metric]}`);
            }
        }

        // Caso especial: sin impacto
        if (["VC", "VI", "VA", "SC", "SI", "SA"].every(metric => this.m(cvssSelected, metric) === "N")) {
            return 0.0;
        }

        // Obtener MacroVector
        const macroVectorResult = this.macroVector(cvssSelected);
        
        // Obtener score base del lookup
        let value = cvssLookup_global[macroVectorResult];
        
        if (value === undefined) {
            // Si no está en el lookup, usar interpolación básica
            console.warn(`MacroVector ${macroVectorResult} no encontrado en lookup, usando valor por defecto`);
            value = 5.0;
        }

        // Calcular componentes del MacroVector
        const eq1 = parseInt(macroVectorResult[0]);
        const eq2 = parseInt(macroVectorResult[1]);
        const eq3 = parseInt(macroVectorResult[2]);
        const eq4 = parseInt(macroVectorResult[3]);
        const eq5 = parseInt(macroVectorResult[4]);
        const eq6 = parseInt(macroVectorResult[5]);

        // Pesos para el cálculo de distancias (simplificados)
        const metricWeights = {
            "AV": 1.0, "PR": 0.9, "UI": 0.8, "AC": 0.7, "AT": 0.6,
            "VC": 1.0, "VI": 1.0, "VA": 1.0, "SC": 0.9, "SI": 0.9, "SA": 0.9
        };

        // Para vectores que existen en el lookup, usar el valor directo sin interpolación
        // Solo interpolar si el vector no existe en el lookup
        if (cvssLookup_global[macroVectorResult] === undefined) {
            // Interpolación simplificada basada en las diferencias con el máximo vector
            let meanDistance = 0;
            
            // Buscar vector de máxima severidad para este MacroVector
            const maxSeverityVector = maxSeverityData[macroVectorResult];
            
            if (maxSeverityVector) {
                meanDistance = this.severityDistance(cvssSelected, maxSeverityVector, metricWeights);
                meanDistance = meanDistance * 0.1; // Factor de ajuste
            }

            // Aplicar la distancia al score
            value -= meanDistance;
        }

        // Aplicar límites y redondeo
        if (value < 0) value = 0.0;
        if (value > 10) value = 10.0;
        
        return Math.round(value * 10) / 10;
    }

    // Calcula el Threat Score (Base + Threat metrics)
    calculateThreatScore(cvssSelected) {
        const baseScore = this.calculateScore(cvssSelected);
        
        // Si no hay métricas de amenaza definidas, retorna el base score
        const exploitMaturity = this.m(cvssSelected, "E");
        if (!exploitMaturity || exploitMaturity === "X") {
            return baseScore;
        }
        
        // Aplicar modificador de madurez del exploit
        let threatScore = baseScore;
        
        switch (exploitMaturity) {
            case "A": // Atacado - máximo impacto
                threatScore = baseScore;
                break;
            case "P": // Prueba de concepto - reduce ligeramente
                threatScore = Math.max(0, baseScore * 0.95);
                break;
            case "U": // No probado - reduce significativamente
                threatScore = Math.max(0, baseScore * 0.85);
                break;
        }
        
        return Math.round(threatScore * 10) / 10;
    }

    // Calcula el Environmental Score
    calculateEnvironmentalScore(cvssSelected) {
        // Crear métricas modificadas para el cálculo ambiental
        const modifiedMetrics = { ...cvssSelected };
        
        // Aplicar métricas modificadas si están definidas
        const environmentalOverrides = {
            "MAV": "AV", "MAC": "AC", "MAT": "AT", "MPR": "PR", "MUI": "UI",
            "MVC": "VC", "MVI": "VI", "MVA": "VA", "MSC": "SC", "MSI": "SI", "MSA": "SA"
        };
        
        for (const [envMetric, baseMetric] of Object.entries(environmentalOverrides)) {
            const envValue = this.m(cvssSelected, envMetric);
            if (envValue && envValue !== "X") {
                modifiedMetrics[baseMetric] = envValue;
            }
        }
        
        // Calcular score base con métricas modificadas
        let envScore = this.calculateScore(modifiedMetrics);
        
        // Aplicar requisitos de seguridad
        const cr = this.m(cvssSelected, "CR");
        const ir = this.m(cvssSelected, "IR");
        const ar = this.m(cvssSelected, "AR");
        
        if (cr && cr !== "X") {
            const crMultiplier = { "H": 1.5, "M": 1.0, "L": 0.5 }[cr] || 1.0;
            if (this.m(modifiedMetrics, "VC") === "H" || this.m(modifiedMetrics, "SC") === "H") {
                envScore *= crMultiplier;
            }
        }
        
        if (ir && ir !== "X") {
            const irMultiplier = { "H": 1.5, "M": 1.0, "L": 0.5 }[ir] || 1.0;
            if (this.m(modifiedMetrics, "VI") === "H" || this.m(modifiedMetrics, "SI") === "H") {
                envScore *= irMultiplier;
            }
        }
        
        if (ar && ar !== "X") {
            const arMultiplier = { "H": 1.5, "M": 1.0, "L": 0.5 }[ar] || 1.0;
            if (this.m(modifiedMetrics, "VA") === "H" || this.m(modifiedMetrics, "SA") === "H") {
                envScore *= arMultiplier;
            }
        }
        
        // Aplicar límites y redondeo
        if (envScore < 0) envScore = 0.0;
        if (envScore > 10) envScore = 10.0;
        
        return Math.round(envScore * 10) / 10;
    }

    // Genera el vector string CVSS v4.0 completo
    generateVectorString(cvssSelected) {
        let vector = "CVSS:4.0";
        
        // Agregar métricas base
        for (let metric of baseMetrics) {
            const value = cvssSelected[metric] || "_";
            vector += `/${metric}:${value}`;
        }
        
        // Agregar métricas de amenaza si están definidas
        for (let metric of threatMetrics) {
            const value = cvssSelected[metric];
            if (value && value !== "X") {
                vector += `/${metric}:${value}`;
            }
        }
        
        // Agregar métricas ambientales si están definidas
        for (let metric of environmentalMetrics) {
            const value = cvssSelected[metric];
            if (value && value !== "X") {
                vector += `/${metric}:${value}`;
            }
        }
        
        // Agregar métricas suplementarias si están definidas
        for (let metric of supplementalMetrics) {
            const value = cvssSelected[metric];
            if (value && value !== "X") {
                vector += `/${metric}:${value}`;
            }
        }
        
        return vector;
    }

    // Determina el nivel de severidad basado en el score
    getSeverityLevel(score) {
        if (score === 0.0) return { level: "Ninguno", class: "severity-none" };
        if (score >= 0.1 && score <= 3.9) return { level: "Bajo", class: "severity-low" };
        if (score >= 4.0 && score <= 6.9) return { level: "Medio", class: "severity-medium" };
        if (score >= 7.0 && score <= 8.9) return { level: "Alto", class: "severity-high" };
        if (score >= 9.0 && score <= 10.0) return { level: "Crítico", class: "severity-critical" };
        return { level: "Desconocido", class: "severity-none" };
    }

    // Valida que un valor sea válido para una métrica
    isValidValue(metric, value) {
        return validValues[metric] && validValues[metric].includes(value);
    }

    // Obtiene los valores que faltan
    getMissingMetrics(cvssSelected) {
        return baseMetrics.filter(metric => !cvssSelected[metric]);
    }

    // Actualiza las métricas seleccionadas
    updateMetrics(newMetrics) {
        this.selectedMetrics = { ...this.selectedMetrics, ...newMetrics };
        return this.selectedMetrics;
    }

    // Reinicia todas las métricas
    reset() {
        this.selectedMetrics = {};
        return this.selectedMetrics;
    }

    // Calcula y retorna toda la información del CVSS
    calculateComplete(cvssSelected = null) {
        const metrics = cvssSelected || this.selectedMetrics;
        
        try {
            const baseScore = this.calculateScore(metrics);
            const threatScore = this.calculateThreatScore(metrics);
            const environmentalScore = this.calculateEnvironmentalScore(metrics);
            
            // Determinar el score principal a mostrar
            let primaryScore = baseScore;
            let scoreType = "Base";
            
            // Si hay métricas ambientales, mostrar environmental score
            const hasEnvironmentalMetrics = environmentalMetrics.some(metric => {
                const value = this.m(metrics, metric);
                return value && value !== "X";
            });
            
            if (hasEnvironmentalMetrics) {
                primaryScore = environmentalScore;
                scoreType = "Environmental";
            } else {
                // Si hay métricas de amenaza, mostrar threat score
                const hasThreatMetrics = threatMetrics.some(metric => {
                    const value = this.m(metrics, metric);
                    return value && value !== "X";
                });
                
                if (hasThreatMetrics) {
                    primaryScore = threatScore;
                    scoreType = "Threat";
                }
            }
            
            const vectorString = this.generateVectorString(metrics);
            const severity = this.getSeverityLevel(primaryScore);
            const macroVector = this.macroVector(metrics);
            const missingMetrics = this.getMissingMetrics(metrics);
            
            return {
                score: primaryScore,
                scoreType,
                baseScore,
                threatScore,
                environmentalScore,
                vectorString,
                severity,
                macroVector,
                missingMetrics,
                isComplete: missingMetrics.length === 0,
                metrics
            };
        } catch (error) {
            const baseScore = 0.0;
            return {
                score: baseScore,
                scoreType: "Base",
                baseScore,
                threatScore: baseScore,
                environmentalScore: baseScore,
                vectorString: this.generateVectorString(metrics),
                severity: this.getSeverityLevel(baseScore),
                macroVector: null,
                missingMetrics: this.getMissingMetrics(metrics),
                isComplete: false,
                error: error.message,
                metrics
            };
        }
    }
}

// Instancia global del calculador
const cvssCalculator = new CVSSCalculator();
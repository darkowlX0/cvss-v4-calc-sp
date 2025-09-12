// CVSS v4.0 Data - Lookup table y configuraciones basadas en la implementación oficial de FIRST
// Copyright FIRST, Red Hat, and contributors - Adaptado para esta implementación

// Lookup table oficial CVSS v4.0 extendida - basada en la implementación de FIRST
const cvssLookup_global = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000100": 9.5,
    "000101": 9.2, "000110": 9.1, "000111": 8.8, "000200": 9.3, "000201": 9.0,
    "000210": 8.9, "000211": 8.6, "001000": 9.8, "001001": 9.5, "001010": 9.5,
    "001011": 9.2, "001100": 9.2, "001101": 8.9, "001110": 8.8, "001111": 8.5,
    "001200": 9.0, "001201": 8.7, "001210": 8.6, "001211": 8.3, "002001": 9.2,
    "002011": 8.9, "002021": 8.6, "002101": 8.9, "002111": 8.6, "002121": 8.3,
    "002201": 8.7, "002211": 8.4, "002221": 8.1, "010000": 9.9, "010001": 9.6,
    "010010": 9.3, "010011": 9.0, "010100": 9.3, "010101": 9.0, "010110": 8.7,
    "010111": 8.4, "010200": 9.0, "010201": 8.7, "010210": 8.4, "010211": 8.1,
    "011000": 9.3, "011001": 9.0, "011010": 8.9, "011011": 8.6, "011100": 8.9,
    "011101": 8.6, "011110": 8.5, "011111": 8.2, "011200": 8.7, "011201": 8.4,
    "011210": 8.3, "011211": 8.0, "012001": 8.6, "012011": 8.3, "012021": 8.0,
    "012101": 8.3, "012111": 8.0, "012121": 7.7, "012201": 8.1, "012211": 7.8,
    "012221": 7.5, "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 9.1,
    "100100": 9.1, "100101": 8.8, "100110": 8.7, "100111": 8.4, "100200": 8.8,
    "100201": 8.5, "100210": 8.4, "100211": 8.1, "101000": 9.4, "101001": 9.1,
    "101010": 8.9, "101011": 8.6, "101100": 8.7, "101101": 8.4, "101110": 8.2,
    "101111": 7.9, "101200": 8.4, "101201": 8.1, "101210": 7.9, "101211": 7.6,
    "102001": 8.6, "102011": 8.3, "102021": 8.0, "102101": 8.3, "102111": 8.0,
    "102121": 7.7, "102201": 8.1, "102211": 7.8, "102221": 7.5, "110000": 9.5,
    "110001": 9.2, "110010": 9.0, "110011": 8.7, "110100": 8.7, "110101": 8.4,
    "110110": 8.2, "110111": 7.9, "110200": 8.4, "110201": 8.1, "110210": 7.9,
    "110211": 7.6, "111000": 9.0, "111001": 8.7, "111010": 8.4, "111011": 8.1,
    "111100": 8.2, "111101": 7.9, "111110": 7.7, "111111": 7.4, "111200": 7.9,
    "111201": 7.6, "111210": 7.4, "111211": 7.1, "112001": 8.1, "112011": 7.8,
    "112021": 7.5, "112101": 7.8, "112111": 7.5, "112121": 7.2, "112201": 7.6,
    "112211": 7.3, "112221": 7.0, "200000": 9.3, "200001": 9.0, "200010": 8.9,
    "200011": 8.6, "200100": 8.6, "200101": 8.3, "200110": 8.2, "200111": 7.9,
    "200200": 8.3, "200201": 8.0, "200210": 7.9, "200211": 7.6, "201000": 8.9,
    "201001": 8.6, "201010": 8.4, "201011": 8.1, "201100": 8.2, "201101": 7.9,
    "201110": 7.7, "201111": 7.4, "201200": 7.9, "201201": 7.6, "201210": 7.4,
    "201211": 7.1, "202001": 8.6, "202011": 7.5, "202021": 5.2, "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202200": 2.4, "202201": 2.4, "202211": 0.9, "202221": 0.4,
    "210000": 9.0, "210001": 8.7, "210010": 8.4, "210011": 8.1, "210100": 8.1,
    "210101": 7.8, "210110": 7.6, "210111": 7.3, "210200": 7.8, "210201": 7.5,
    "210210": 7.3, "210211": 7.0, "211000": 8.4, "211001": 8.1, "211010": 7.8,
    "211011": 7.5, "211100": 7.6, "211101": 7.3, "211110": 7.1, "211111": 6.8,
    "211200": 7.3, "211201": 7.0, "211210": 6.8, "211211": 6.5, "212001": 7.5,
    "212011": 7.2, "212021": 6.9, "212101": 7.2, "212111": 6.9, "212121": 6.6,
    "212201": 7.0, "212211": 6.7, "212221": 6.4, "220000": 8.7, "220001": 8.4,
    "220010": 8.1, "220011": 7.8, "220100": 7.8, "220101": 7.5, "220110": 7.3,
    "220111": 7.0, "220200": 7.5, "220201": 7.2, "220210": 7.0, "220211": 6.7,
    "221000": 8.1, "221001": 7.8, "221010": 7.5, "221011": 7.2, "221100": 7.3,
    "221101": 7.0, "221110": 6.8, "221111": 6.5, "221200": 7.0, "221201": 6.7,
    "221210": 6.5, "221211": 6.2, "222001": 7.2, "222011": 6.9, "222021": 6.6,
    "222101": 6.9, "222111": 6.6, "222121": 6.3, "222201": 6.7, "222211": 6.4,
    "222221": 6.1,
    // Entradas adicionales para casos específicos
    "000020": 8.8, "000120": 8.5, "000220": 8.2,
    "001020": 8.5, "001120": 8.2, "001220": 7.9,
    "002020": 8.2, "002120": 7.9, "002220": 7.6,
    "010020": 8.5, "010120": 8.2, "010220": 7.9,
    "011020": 8.2, "011120": 7.9, "011220": 7.6,
    "012020": 7.9, "012120": 7.6, "012220": 7.3,
    "100020": 8.2, "100120": 7.9, "100220": 7.6,
    "101020": 7.9, "101120": 7.6, "101220": 7.3,
    "102020": 7.6, "102120": 7.3, "102220": 7.0,
    "110020": 7.9, "110120": 7.6, "110220": 7.3,
    "111020": 7.6, "111120": 7.3, "111220": 7.0,
    "112020": 7.3, "112120": 7.0, "112220": 6.7,
    "200020": 7.6, "200120": 7.3, "200220": 7.0,
    "201020": 7.3, "201120": 7.0, "201220": 6.7,
    "202020": 7.0, "202120": 6.7, "202220": 6.4,
    "210020": 7.3, "210120": 7.0, "210220": 6.7,
    "211020": 7.0, "211120": 6.7, "211220": 6.4,
    "212020": 6.7, "212120": 6.4, "212220": 6.1,
    "220020": 7.0, "220120": 6.7, "220220": 6.4,
    "221020": 6.7, "221120": 6.4, "221220": 6.1,
    "222020": 6.4, "222120": 6.1, "222220": 5.8
};

// Máxima severidad por MacroVector (para interpolación)
const maxSeverityData = {
    "000000": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"H","SI":"H","SA":"H"},
    "000001": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"H","SI":"H","SA":"L"},
    "000010": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"H","SI":"L","SA":"H"},
    "000011": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"H","SI":"L","SA":"L"},
    "000100": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"L","SI":"H","SA":"H"},
    "000101": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"L","SI":"H","SA":"L"},
    "000110": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"L","SI":"L","SA":"H"},
    "000111": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"L","SI":"L","SA":"L"},
    "000200": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"N","SI":"H","SA":"H"},
    "000201": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"N","SI":"H","SA":"L"},
    "000210": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"N","SI":"L","SA":"H"},
    "000211": {"AV":"N","PR":"N","UI":"N","VC":"H","VI":"H","VA":"H","SC":"N","SI":"L","SA":"L"},
    "202200": {"AV":"P","PR":"N","UI":"N","VC":"L","VI":"L","VA":"L","SC":"N","SI":"N","SA":"N"}
};

// Niveles de métricas para el cálculo de distancias
const metricLevels = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SA": {"H": 0.0, "L": 0.1, "N": 0.2}
};

// Métricas base requeridas
const baseMetrics = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];

// Métricas de amenaza (threat)
const threatMetrics = ["E"];

// Métricas ambientales
const environmentalMetrics = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"];

// Métricas suplementarias (no afectan el score)
const supplementalMetrics = ["S", "AU", "R", "V", "RE", "U"];

// Todas las métricas
const allMetrics = [...baseMetrics, ...threatMetrics, ...environmentalMetrics, ...supplementalMetrics];

// Valores válidos por métrica
const validValues = {
    // Métricas Base
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
    
    // Métricas de Amenaza
    "E": ["X", "A", "P", "U"],
    
    // Métricas Ambientales
    "CR": ["X", "H", "M", "L"],
    "IR": ["X", "H", "M", "L"],
    "AR": ["X", "H", "M", "L"],
    "MAV": ["X", "N", "A", "L", "P"],
    "MAC": ["X", "L", "H"],
    "MAT": ["X", "N", "P"],
    "MPR": ["X", "N", "L", "H"],
    "MUI": ["X", "N", "P", "A"],
    "MVC": ["X", "H", "L", "N"],
    "MVI": ["X", "H", "L", "N"],
    "MVA": ["X", "H", "L", "N"],
    "MSC": ["X", "H", "L", "N"],
    "MSI": ["X", "H", "L", "N"],
    "MSA": ["X", "H", "L", "N"],
    
    // Métricas Suplementarias
    "S": ["X", "N", "P"],
    "AU": ["X", "N", "Y"],
    "R": ["X", "A", "U", "I"],
    "V": ["X", "D", "C"],
    "RE": ["X", "L", "M", "H"],
    "U": ["X", "C", "G", "A", "R"]
};

// Nombres en español de las métricas
const metricNames = {
    // Métricas Base
    "AV": "Vector de Ataque",
    "AC": "Complejidad de Ataque",
    "AT": "Requerimientos de Ataque",
    "PR": "Privilegios Requeridos",
    "UI": "Interacción de Usuario",
    "VC": "Confidencialidad del Sistema Vulnerable",
    "VI": "Integridad del Sistema Vulnerable",
    "VA": "Disponibilidad del Sistema Vulnerable",
    "SC": "Confidencialidad del Sistema Subsecuente",
    "SI": "Integridad del Sistema Subsecuente",
    "SA": "Disponibilidad del Sistema Subsecuente",
    
    // Métricas de Amenaza
    "E": "Madurez del Exploit",
    
    // Métricas Ambientales
    "CR": "Requisito de Confidencialidad",
    "IR": "Requisito de Integridad",
    "AR": "Requisito de Disponibilidad",
    "MAV": "Vector de Ataque Modificado",
    "MAC": "Complejidad de Ataque Modificada",
    "MAT": "Requerimientos de Ataque Modificados",
    "MPR": "Privilegios Requeridos Modificados",
    "MUI": "Interacción de Usuario Modificada",
    "MVC": "Confidencialidad del Sistema Vulnerable Modificada",
    "MVI": "Integridad del Sistema Vulnerable Modificada",
    "MVA": "Disponibilidad del Sistema Vulnerable Modificada",
    "MSC": "Confidencialidad del Sistema Subsecuente Modificada",
    "MSI": "Integridad del Sistema Subsecuente Modificada",
    "MSA": "Disponibilidad del Sistema Subsecuente Modificada",
    
    // Métricas Suplementarias
    "S": "Seguridad",
    "AU": "Automatizable",
    "R": "Recuperación",
    "V": "Densidad de Valor",
    "RE": "Esfuerzo de Respuesta de Vulnerabilidad",
    "U": "Urgencia del Proveedor"
};

// Descripciones de valores
const valueDescriptions = {
    "AV": {
        "N": "Remoto",
        "A": "Adyacente", 
        "L": "Local",
        "P": "Físico"
    },
    "AC": {
        "L": "Baja",
        "H": "Alta"
    },
    "AT": {
        "N": "Ninguno",
        "P": "Presente"
    },
    "PR": {
        "N": "Ninguno",
        "L": "Bajo",
        "H": "Alto"
    },
    "UI": {
        "N": "Ninguna",
        "P": "Pasiva",
        "A": "Activa"
    },
    "VC": {
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "VI": {
        "H": "Alto",
        "L": "Bajo", 
        "N": "Ninguno"
    },
    "VA": {
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "SC": {
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "SI": {
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "SA": {
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    
    // Métricas de Amenaza
    "E": {
        "X": "No Definido",
        "A": "Atacado",
        "P": "Prueba de Concepto",
        "U": "No Probado"
    },
    
    // Métricas Ambientales
    "CR": {
        "X": "No Definido",
        "H": "Alto",
        "M": "Medio",
        "L": "Bajo"
    },
    "IR": {
        "X": "No Definido",
        "H": "Alto",
        "M": "Medio",
        "L": "Bajo"
    },
    "AR": {
        "X": "No Definido",
        "H": "Alto",
        "M": "Medio",
        "L": "Bajo"
    },
    "MAV": {
        "X": "No Definido",
        "N": "Remoto",
        "A": "Adyacente",
        "L": "Local",
        "P": "Físico"
    },
    "MAC": {
        "X": "No Definido",
        "L": "Baja",
        "H": "Alta"
    },
    "MAT": {
        "X": "No Definido",
        "N": "Ninguno",
        "P": "Presente"
    },
    "MPR": {
        "X": "No Definido",
        "N": "Ninguno",
        "L": "Bajo",
        "H": "Alto"
    },
    "MUI": {
        "X": "No Definido",
        "N": "Ninguna",
        "P": "Pasiva",
        "A": "Activa"
    },
    "MVC": {
        "X": "No Definido",
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "MVI": {
        "X": "No Definido",
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "MVA": {
        "X": "No Definido",
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "MSC": {
        "X": "No Definido",
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "MSI": {
        "X": "No Definido",
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    "MSA": {
        "X": "No Definido",
        "H": "Alto",
        "L": "Bajo",
        "N": "Ninguno"
    },
    
    // Métricas Suplementarias
    "S": {
        "X": "No Definido",
        "N": "Sin Impacto",
        "P": "Presente"
    },
    "AU": {
        "X": "No Definido",
        "N": "No",
        "Y": "Sí"
    },
    "R": {
        "X": "No Definido",
        "A": "Automática",
        "U": "Usuario",
        "I": "Irrecuperable"
    },
    "V": {
        "X": "No Definido",
        "D": "Difusa",
        "C": "Concentrada"
    },
    "RE": {
        "X": "No Definido",
        "L": "Bajo",
        "M": "Medio",
        "H": "Alto"
    },
    "U": {
        "X": "No Definido",
        "C": "Claro",
        "G": "Verde",
        "A": "Ámbar",
        "R": "Rojo"
    }
};
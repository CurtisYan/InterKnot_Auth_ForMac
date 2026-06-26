import Foundation
import CoreImage
import Vision

// MARK: - Captcha Service

final class CaptchaService {
    
    /// Attempt automatic captcha recognition using Vision.
    /// Returns the recognized text or nil if confidence is too low.
    static func recognize(imageData: Data) -> String? {
        guard let ciImage = CIImage(data: imageData) else { return nil }
        
        // Preprocess
        guard let processed = preprocessCaptchaImage(ciImage) else { return nil }
        
        // Use VNRecognizeTextRequest
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        request.customWords = ["0","1","2","3","4","5","6","7","8","9"]
        
        let handler = VNImageRequestHandler(ciImage: processed)
        try? handler.perform([request])
        
        guard let results = request.results, !results.isEmpty else { return nil }
        
        // Find the best candidate (highest confidence, only digits)
        var bestResult: String?
        var bestConfidence: Float = 0
        
        for observation in results {
            guard let candidate = observation.topCandidates(1).first else { continue }
            let text = candidate.string.trimmingCharacters(in: .whitespacesAndNewlines)
            // Filter to only digits (typical Chinese campus captchas)
            let digits = text.filter { $0.isNumber }
            let confidence = candidate.confidence
            
            if confidence > bestConfidence, !digits.isEmpty {
                bestResult = digits
                bestConfidence = confidence
            }
        }
        
        guard let result = bestResult, bestConfidence > 0.5 else { return nil }
        Logger.write("Captcha auto-recognized: \(result) (confidence: \(bestConfidence))")
        return result
    }
    
    private static func preprocessCaptchaImage(_ input: CIImage) -> CIImage? {
        // Step 1: Desaturate (grayscale)
        let grayscale = input.applyingFilter("CIColorControls", parameters: [
            kCIInputSaturationKey: 0.0,
        ])
        
        // Step 2: Increase contrast
        let contrasted = grayscale.applyingFilter("CIColorControls", parameters: [
            kCIInputContrastKey: 2.0,
        ])
        
        // Step 3: Apply threshold via color monochrome
        let threshold = contrasted.applyingFilter("CIColorMonochrome", parameters: [
            kCIInputColorKey: CIColor.black,
            kCIInputIntensityKey: 1.0,
        ])
        
        return threshold
    }
}

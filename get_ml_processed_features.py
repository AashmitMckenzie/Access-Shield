import pandas as pd
import numpy as np
import os

def prepare_ml_features(input_file="ml_training_features.csv", output_file="ml_processed_features.csv"):
    """
    Process the ML training features to create processed features for ML model training.
    
    Args:
        input_file (str): Path to the input CSV file with training features
        output_file (str): Path to save the processed features
    """
    print(f"Processing ML features from {input_file}...")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found!")
        return False
    
    try:
        # Load data
        df = pd.read_csv(input_file)
        print(f"Loaded {len(df)} samples")
        
        # Feature engineering
        
        # 1. Time-based features - cyclic encoding for time variables
        df['hour_sin'] = np.sin(2 * np.pi * df['hour_of_day'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour_of_day'] / 24)
        df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
        df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
        
        # 2. Categorical encoding for geographical features
        # Handle missing or empty values
        df['geo_continent'] = df['geo_continent'].fillna('Unknown')
        df['geo_country'] = df['geo_country'].fillna('Unknown')
        
        # One-hot encode continent and country features
        geo_continent_dummies = pd.get_dummies(df['geo_continent'], prefix='continent')
        geo_country_dummies = pd.get_dummies(df['geo_country'], prefix='country')
        
        # Limit country features to avoid too many dimensions
        top_countries = geo_country_dummies.sum().sort_values(ascending=False).head(20).index
        geo_country_dummies = geo_country_dummies[top_countries]
        
        # 3. Combine all features
        # Safely drop columns that might not exist
        columns_to_drop = ['geo_continent', 'geo_country', 'device_fingerprint', 'request_id']
        existing_columns = [col for col in columns_to_drop if col in df.columns]
        
        feature_df = pd.concat([
            df.drop(existing_columns, axis=1),
            geo_continent_dummies,
            geo_country_dummies
        ], axis=1)
        
        # Save processed features
        feature_df.to_csv(output_file, index=False)
        print(f"✅ ML features prepared and saved to {output_file}")
        
        # Display class distribution
        attack_count = feature_df['attack_detected'].sum()
        total = len(feature_df)
        print(f"Class distribution:")
        print(f"- Normal requests: {total - attack_count} ({(total - attack_count) / total:.2%})")
        print(f"- Attack requests: {attack_count} ({attack_count / total:.2%})")
        
        return True
        
    except Exception as e:
        print(f"Error preparing ML features: {e}")
        return False

if __name__ == "__main__":
    # You can customize the input and output file paths here
    input_file = "ml_training_features.csv"
    output_file = "ml_processed_features.csv"
    
    # Ask user for custom file paths
    custom_input = input(f"Enter input file path (default: {input_file}): ").strip()
    if custom_input:
        input_file = custom_input
        
    custom_output = input(f"Enter output file path (default: {output_file}): ").strip()
    if custom_output:
        output_file = custom_output
    
    # Process the features
    success = prepare_ml_features(input_file, output_file)
    
    if success:
        print("Processing completed successfully!")
    else:
        print("Processing failed. Check the error messages above.")
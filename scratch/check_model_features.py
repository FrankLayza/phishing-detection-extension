import json

m = json.load(open('phishing-extension/assets/phishing_model.json'))
features_used = set()

def traverse(node):
    if 'f' in node:
        features_used.add(node['f'])
        traverse(node['l'])
        traverse(node['r'])

for t in m['trees']:
    traverse(t)

print("Features used in trees (indices):", sorted(list(features_used)))
print("Number of features used:", len(features_used))

# Print the names of the features used
names = m['feature_names']
used_names = [names[i] for i in sorted(list(features_used))]
print("\nFeature names used:")
for i, name in enumerate(used_names):
    print(f"  {i+1}. {name} (index {names.index(name)})")

# Print the names of the features NOT used
unused_names = [name for name in names if name not in used_names]
print("\nFeature names NOT used:")
for i, name in enumerate(unused_names):
    print(f"  {i+1}. {name} (index {names.index(name)})")

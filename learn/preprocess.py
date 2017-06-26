def create_field_name_dict(field_names):
	field_arr = []
	for field in field_names:
		field_arr.append({})

	return field_arr

def preprocess_training_file(file_name):
	file = open(file_name)

	field_names = {
		'field_name': {
			'label_name': 0 # int_value
		}
	}

	lineNum = 0
	for line in file:
		line_arr = line.split(',')

		if lineNum == 0:
			field_names = create_field_name_dict(line_arr)
			continue

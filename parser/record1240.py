reader = DEReader(record.payload)

mti = reader.read_ebcdic(4)

bitmap = Bitmap.from_reader(reader)

present = bitmap.present_des()

for de in present:

    if de == 1:
        continue

    field = metadata[str(de)]

    value = FieldReader.read(reader, field)

    record[de] = value
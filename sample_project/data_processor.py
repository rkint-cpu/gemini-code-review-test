def find_duplicate_ids(list_a: list[int], list_b: list[int]) -> list[int]:
    duplicates = []
    for item_a in list_a:
        for item_b in list_b:
            if item_a == item_b and item_a not in duplicates:
                duplicates.append(item_a)
    return duplicates
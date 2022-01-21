def parent(i):
    return (i - 1) // 2


def left(i):
    return 2 * i + 1


def right(i):
    return 2 * i + 2


class heapsort:

    def __init__(self, alist=None):
        """
        Func for reshuffle arr to new arr with ascending sort
        :param alist:
        """
        self.alist = alist

    def heapsort(self):
        self.build_max_heap()
        for i in range(len(self.alist) - 1, 0, -1):
            self.alist[0], self.alist[i] = self.alist[i], self.alist[0]
            self.max_heapify(index=0, size=i)

    def build_max_heap(self):
        length = len(self.alist)
        start = parent(length - 1)
        while start >= 0:
            self.max_heapify(index=start, size=length)
            start = start - 1

    def max_heapify(self, index, size):
        l = left(index)
        r = right(index)
        if l < size and self.alist[l] > self.alist[index]:
            largest = l
        else:
            largest = index
        if r < size and self.alist[r] > self.alist[largest]:
            largest = r
        if largest != index:
            self.alist[largest], self.alist[index] = self.alist[index], self.alist[largest]
            self.max_heapify(largest, size)

    def main(self):
        self.heapsort()
        print('Sorted list: ', end='')
        print(self.alist)
        return self.alist
